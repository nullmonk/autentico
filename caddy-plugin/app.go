package caddy_plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/coreos/go-oidc/v3/oidc"
)

func init() {
	caddy.RegisterModule(AutenticoApp{})
	httpcaddyfile.RegisterGlobalOption("autentico", parseAutenticoGlobalApp)
}

// AutenticoApp represents the global Autentico app configuration.
type AutenticoApp struct {
	Servers map[string]*ServerConfig `json:"servers,omitempty"`

	providers map[string]*oidc.Provider
}

// ServerConfig holds configuration for a specific Autentico server.
type ServerConfig struct {
	URL          string `json:"url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// CaddyModule returns the Caddy module information.
func (AutenticoApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "autentico",
		New: func() caddy.Module { return new(AutenticoApp) },
	}
}

// Provision sets up the app and caches OIDC providers.
func (a *AutenticoApp) Provision(ctx caddy.Context) error {
	a.providers = make(map[string]*oidc.Provider)
	for name, srv := range a.Servers {
		issuer := strings.TrimSuffix(srv.URL, "/")
		provider, err := oidc.NewProvider(context.Background(), issuer)
		if err != nil {
			return fmt.Errorf("failed to provision provider for %s: %w", name, err)
		}
		a.providers[name] = provider
	}
	return nil
}

// GetProvider retrieves the cached provider
func (a *AutenticoApp) GetProvider(serverName string) (*oidc.Provider, error) {
	if a.providers == nil {
		return nil, fmt.Errorf("providers not initialized")
	}
	p, ok := a.providers[serverName]
	if !ok {
		return nil, fmt.Errorf("provider for %s not found", serverName)
	}
	return p, nil
}

// Start starts the app.
func (a *AutenticoApp) Start() error {
	return nil
}

// Stop stops the app.
func (a *AutenticoApp) Stop() error {
	return nil
}

// parseAutenticoGlobalApp parses the global `autentico` Caddyfile directive.
func parseAutenticoGlobalApp(d *caddyfile.Dispenser, existingVal interface{}) (interface{}, error) {
	app := &AutenticoApp{
		Servers: make(map[string]*ServerConfig),
	}

	if existingVal != nil {
		app = existingVal.(*AutenticoApp)
		if app.Servers == nil {
			app.Servers = make(map[string]*ServerConfig)
		}
	}

	// Skip 'autentico'
	d.Next()

	for d.NextBlock(0) {
		if d.Val() != "server" {
			return nil, d.Errf("expected 'server', got %s", d.Val())
		}

		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		serverName := d.Val()

		serverConfig := &ServerConfig{}
		nest := d.Nesting()
		for d.NextBlock(nest) {
			switch d.Val() {
			case "url":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				serverConfig.URL = d.Val()
			case "client_id":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				serverConfig.ClientID = d.Val()
			case "client_secret":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				serverConfig.ClientSecret = d.Val()
			default:
				return nil, d.Errf("unrecognized subdirective %s", d.Val())
			}
		}

		if serverConfig.URL == "" {
			return nil, fmt.Errorf("server %s missing URL", serverName)
		}

		app.Servers[serverName] = serverConfig
	}

	return app, nil
}

// Interface guards
var (
	_ caddy.App         = (*AutenticoApp)(nil)
	_ caddy.Provisioner = (*AutenticoApp)(nil)
)
