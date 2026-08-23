package account

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestHandler_WithAccountOverride(t *testing.T) {
	dir := t.TempDir()
	overrideDir := filepath.Join(dir, "account")
	assert.NoError(t, os.MkdirAll(overrideDir, 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(overrideDir, "index.html"), []byte("<html>OVERRIDDEN DASHBOARD</html>"), 0644))
	assert.NoError(t, os.WriteFile(filepath.Join(overrideDir, "dashboard.js"), []byte("console.log('dash')"), 0644))

	orig := config.Bootstrap
	defer func() { config.Bootstrap = orig }()
	config.Bootstrap.TemplatesDir = dir

	// A route that doesn't match a file falls back to index.html
	req := httptest.NewRequest("GET", "/account/", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	assert.Equal(t, 200, rec.Code)
	assert.Equal(t, "<html>OVERRIDDEN DASHBOARD</html>", rec.Body.String())

	// A real file alongside index.html is served as-is
	req = httptest.NewRequest("GET", "/account/dashboard.js", nil)
	rec = httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	assert.Equal(t, 200, rec.Code)
	assert.Equal(t, "console.log('dash')", rec.Body.String())
}

func TestHandler_WithoutAccountOverride_FallsBackToEmbedded(t *testing.T) {
	orig := config.Bootstrap
	defer func() { config.Bootstrap = orig }()
	config.Bootstrap.TemplatesDir = t.TempDir() // exists, but no account/index.html

	req := httptest.NewRequest("GET", "/account/", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	// Embedded dist isn't built in this environment, so this exercises the
	// "not built" fallback path rather than a real index.html — it should
	// not panic and should not serve the override content.
	assert.NotEqual(t, "<html>OVERRIDDEN DASHBOARD</html>", rec.Body.String())
}
