package caddy_plugin

import (
	"reflect"
	"testing"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseAutenticoHandler_AllowInline(t *testing.T) {
	input := `autentico allow roles editor viewer`
	d := caddyfile.NewTestDispenser(input)

	// Consume 'autentico' as Caddy would normally
	d.Next()

	args := d.RemainingArgs()
	if len(args) == 0 || args[0] != "allow" {
		t.Fatalf("Expected first arg to be allow, got %v", args)
	}

	rule := &AllowRule{Server: "default"}
	idx := 1
	if idx < len(args) && args[idx] != "roles" {
		rule.Server = args[idx]
		idx++
	}
	if idx >= len(args) || args[idx] != "roles" {
		t.Fatalf("expected 'roles', got %v", args)
	}
	rule.Roles = args[idx+1:]

	if rule.Server != "default" {
		t.Errorf("Expected server 'default', got %s", rule.Server)
	}
	if !reflect.DeepEqual(rule.Roles, []string{"editor", "viewer"}) {
		t.Errorf("Expected roles [editor viewer], got %v", rule.Roles)
	}
}

func TestParseAutenticoHandler_AllowInlineExplicitServer(t *testing.T) {
	input := `autentico allow compliance_srv roles auditor`
	d := caddyfile.NewTestDispenser(input)

	d.Next()

	args := d.RemainingArgs()
	rule := &AllowRule{Server: "default"}
	idx := 1
	if idx < len(args) && args[idx] != "roles" {
		rule.Server = args[idx]
		idx++
	}
	if idx >= len(args) || args[idx] != "roles" {
		t.Fatalf("expected 'roles', got %v", args)
	}
	rule.Roles = args[idx+1:]

	if rule.Server != "compliance_srv" {
		t.Errorf("Expected server 'compliance_srv', got %s", rule.Server)
	}
	if !reflect.DeepEqual(rule.Roles, []string{"auditor"}) {
		t.Errorf("Expected roles [auditor], got %v", rule.Roles)
	}
}

// Full parsing using the block mechanism
func TestParseAllowBlock(t *testing.T) {
	input := `allow compliance_srv {
		roles auditor
	}`

	d := caddyfile.NewTestDispenser(input)
	d.Next() // consume "allow"

	rule, err := parseAllowBlock(d)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	allowRule, ok := rule.(*AllowRule)
	if !ok {
		t.Fatalf("Expected *AllowRule")
	}

	if allowRule.Server != "compliance_srv" {
		t.Errorf("Expected server 'compliance_srv', got %s", allowRule.Server)
	}
	if !reflect.DeepEqual(allowRule.Roles, []string{"auditor"}) {
		t.Errorf("Expected roles [auditor], got %v", allowRule.Roles)
	}
}
