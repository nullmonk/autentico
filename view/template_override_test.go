package view

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplate_WithOverrideDir(t *testing.T) {
	// Setup custom templates dir
	dir := t.TempDir()

	err := os.WriteFile(filepath.Join(dir, "login.html"), []byte(`{{define "content"}}OVERRIDDEN LOGIN{{end}}`), 0644)
	assert.NoError(t, err)

	// Save original config
	orig := config.Bootstrap
	defer func() { config.Bootstrap = orig }()

	config.Bootstrap.TemplatesDir = dir

	tmpl, err := ParseTemplate("login")
	assert.NoError(t, err)

	var buf strings.Builder
	err = tmpl.ExecuteTemplate(&buf, "content", nil)
	assert.NoError(t, err)

	assert.Equal(t, "OVERRIDDEN LOGIN", buf.String())
}
