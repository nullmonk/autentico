package caddy_plugin

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(AutenticoHandler{})
	httpcaddyfile.RegisterHandlerDirective("autentico", parseAutenticoHandler)
}

// AutenticoHandler is the HTTP middleware handler.
type AutenticoHandler struct {
	Rules         []Rule   `json:"rules,omitempty"`
	InjectHeaders bool     `json:"inject_headers,omitempty"`

	ctx caddy.Context
}

// CaddyModule returns the Caddy module information.
func (AutenticoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.autentico",
		New: func() caddy.Module { return new(AutenticoHandler) },
	}
}

// Provision sets up the module.
func (h *AutenticoHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *AutenticoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return handleOAuth2(h, w, r, next)
}

// parseRequireAll parses the require_all directive inside autentico
func parseRequireAll(d *caddyfile.Dispenser) (Rule, error) {
	rule := &RequireAllRule{}
	nest := d.Nesting()
	for d.NextBlock(nest) {
		switch d.Val() {
		case "allow":
			allowRule, err := parseAllowBlock(d)
			if err != nil {
				return nil, err
			}
			rule.Rules = append(rule.Rules, allowRule)
		case "require_all":
			reqAllRule, err := parseRequireAll(d)
			if err != nil {
				return nil, err
			}
			rule.Rules = append(rule.Rules, reqAllRule)
		default:
			return nil, d.Errf("unknown require_all subdirective: %s", d.Val())
		}
	}
	return rule, nil
}

// parseAllowBlock handles both single line and block allow directives correctly
func parseAllowBlock(d *caddyfile.Dispenser) (Rule, error) {
	rule := &AllowRule{Server: "default"}

	// Check if the argument is a block or inline
	args := d.RemainingArgs()
	if len(args) > 0 {
		// If the first arg is not "roles", it's the server name
		idx := 0
		if args[0] != "roles" && args[0] != "{" {
			rule.Server = args[0]
			idx++
		}

		// If there are still args on this line, it's an inline definition
		if idx < len(args) && args[idx] == "roles" {
			rule.Roles = args[idx+1:]
			return rule, nil
		}
	}

	// Otherwise, it's a block
	nest := d.Nesting()
	for d.NextBlock(nest) {
		switch d.Val() {
		case "roles":
			rule.Roles = append(rule.Roles, d.RemainingArgs()...)
		case "server":
			if !d.Args(&rule.Server) {
				return nil, d.ArgErr()
			}
		default:
			return nil, d.Errf("unknown allow subdirective: %s", d.Val())
		}
	}

	return rule, nil
}


func parseAutenticoHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler AutenticoHandler
	d := h.Dispenser

	// Consume 'autentico'
	d.Next()

	// Check if inline allow "autentico allow roles editor viewer"
	args := d.RemainingArgs()
	if len(args) > 0 {
		if args[0] == "allow" {
			rule := &AllowRule{Server: "default"}
			idx := 1
			if idx < len(args) && args[idx] != "roles" {
				rule.Server = args[idx]
				idx++
			}
			if idx >= len(args) || args[idx] != "roles" {
				return nil, fmt.Errorf("expected 'roles', got %v", args)
			}
			rule.Roles = args[idx+1:]
			handler.Rules = append(handler.Rules, rule)
			return &handler, nil
		}
		return nil, fmt.Errorf("unrecognized inline argument: %s", args[0])
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "allow":
			allowRule, err := parseAllowBlock(d)
			if err != nil {
				return nil, err
			}
			handler.Rules = append(handler.Rules, allowRule)
		case "require_all":
			reqAllRule, err := parseRequireAll(d)
			if err != nil {
				return nil, err
			}
			handler.Rules = append(handler.Rules, reqAllRule)
		case "inject":
			args := d.RemainingArgs()
			if len(args) >= 3 && args[0] == "headers" && args[1] == "with" && args[2] == "claims" {
				handler.InjectHeaders = true
			} else {
				return nil, d.Errf("expected 'inject headers with claims', got 'inject %v'", args)
			}
		default:
			return nil, d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	return &handler, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AutenticoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*AutenticoHandler)(nil)
)
