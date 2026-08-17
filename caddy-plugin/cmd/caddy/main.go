package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// plug in the Autentico plugin
	_ "github.com/eugenioenko/autentico/caddy-plugin"
)

func main() {
	caddycmd.Main()
}
