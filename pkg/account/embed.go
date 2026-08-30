package account

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the account UI.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	var embedded http.Handler
	if err != nil {
		embedded = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Account UI not built. Run 'make build' or 'make account-ui-build'.", http.StatusNotFound)
		})
	} else {
		embedded = spaHandler(http.FS(sub))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if templatesDir := config.GetBootstrap().TemplatesDir; templatesDir != "" {
			overrideDir := filepath.Join(templatesDir, "account")
			if _, err := os.Stat(filepath.Join(overrideDir, "index.html")); err == nil {
				spaHandler(http.Dir(overrideDir)).ServeHTTP(w, r)
				return
			}
		}
		embedded.ServeHTTP(w, r)
	})
}

// spaHandler serves files from root under the /account/ prefix, falling
// back to index.html for any path that isn't an actual file, so
// client-side routing works whether root is the embedded dist or a
// TemplatesDir override.
func spaHandler(root http.FileSystem) http.Handler {
	fileServer := http.FileServer(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /account/ prefix
		path := strings.TrimPrefix(r.URL.Path, "/account")
		if path == "" {
			path = "/"
		}

		// Try to open the file to see if it exists
		if path != "/" {
			trimmed := strings.TrimPrefix(path, "/")
			if f, err := root.Open(trimmed); err == nil {
				_ = f.Close()
				// Content-hashed assets are safe to cache for a year
				if strings.HasPrefix(path, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					// favicon and other root-level files: 1 day
					w.Header().Set("Cache-Control", "public, max-age=86400")
				}
				http.StripPrefix("/account", fileServer).ServeHTTP(w, r)
				return
			}
		}

		// The fallback page must not be cached so the browser picks up
		// changes (new asset URLs after a deploy, or an edited override)
		w.Header().Set("Cache-Control", "no-cache")
		serveIndex(w, r, root)
	})
}

// serveIndex writes index.html directly via http.ServeContent rather than
// routing through http.FileServer, which special-cases any path ending in
// "/index.html" with a redirect to "./" — for a request already at
// "/account/" that resolves right back to itself, an infinite redirect loop.
func serveIndex(w http.ResponseWriter, r *http.Request, root http.FileSystem) {
	f, err := root.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() {
		_ = f.Close()
	}()

	stat, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	http.ServeContent(w, r, "index.html", stat.ModTime(), f)
}
