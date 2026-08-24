package view

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestStaticHandler_WithOverrideDir(t *testing.T) {
	dir := t.TempDir()
	staticDir := filepath.Join(dir, "static")
	assert.NoError(t, os.MkdirAll(staticDir, 0755))
	assert.NoError(t, os.WriteFile(filepath.Join(staticDir, "main.js"), []byte("console.log('overridden')"), 0644))

	orig := config.Bootstrap
	defer func() { config.Bootstrap = orig }()
	config.Bootstrap.TemplatesDir = dir

	req := httptest.NewRequest("GET", "/main.js", nil)
	rec := httptest.NewRecorder()
	StaticHandler().ServeHTTP(rec, req)

	assert.Equal(t, 200, rec.Code)
	assert.Equal(t, "console.log('overridden')", rec.Body.String())
}

func TestStaticHandler_FallsBackToEmbedded(t *testing.T) {
	orig := config.Bootstrap
	defer func() { config.Bootstrap = orig }()
	config.Bootstrap.TemplatesDir = t.TempDir() // exists, but has no static/ override

	req := httptest.NewRequest("GET", "/auth.css", nil)
	rec := httptest.NewRecorder()
	StaticHandler().ServeHTTP(rec, req)

	assert.Equal(t, 200, rec.Code)
	assert.NotEmpty(t, rec.Body.String())
}
