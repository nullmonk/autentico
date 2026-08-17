# Autentico Caddy Plugin

This is a Caddy plugin that acts as an OIDC authentication proxy using [Autentico](https://github.com/eugenioenko/autentico) as the Identity Provider. It intercepts requests, handles the OAuth2 Authorization Code flow, and enforces role-based access control policies before proxying traffic to your backend services.

## Features

- Native Caddyfile syntax integration.
- Supports multiple distinct Autentico servers.
- Complex role-based access control with `require_all` and `allow` blocks.
- Secure, cryptographically signed (HMAC-SHA256) session cookies.
- Automatic injection of user claims into `X-Autentico-*` HTTP headers.

## Building Caddy with the Plugin

The easiest way to build Caddy with this plugin is using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
# Install xcaddy if you haven't already
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with the Autentico plugin included
xcaddy build --with github.com/eugenioenko/autentico/caddy-plugin=./caddy-plugin
```

## Configuration

The plugin uses a global configuration block to define your Autentico server(s), and an HTTP directive in your routes to enforce policies.

### Global Configuration

At the top of your `Caddyfile`, define your Autentico servers:

```caddyfile
{
    autentico {
        server default {
            url http://autentico:9999
            client_id my_caddy_client
            client_secret super_secret_string
        }
        server compliance_srv {
            url https://auth.compliance.internal
            client_id compliance_client
            client_secret compliance_secret
        }
    }
}
```

### Route Configuration Examples

Inside your domain block, use the `autentico` directive to protect routes.

**1. Basic Role Requirement (Implicit Default Server)**
```caddyfile
example.com {
    route /dashboard/* {
        autentico allow roles editor viewer
        reverse_proxy localhost:8080
    }
}
```

**2. Block Syntax and Header Injection**
```caddyfile
example.com {
    route /settings/* {
        autentico {
            allow {
                roles admin
            }
            inject headers with claims
        }
        reverse_proxy localhost:8081
    }
}
```

**3. Multi-Server and Complex Policies**
Evaluates to: `(admin@default AND auditor@compliance_srv) OR superadmin@default`

```caddyfile
example.com {
    route /audit/* {
        autentico {
            require_all {
                allow roles admin                 # Assumes "default" server
                allow compliance_srv roles auditor # Explicit server
            }
            allow roles superadmin                # Assumes "default" server
            inject headers with claims
        }
        reverse_proxy localhost:8082
    }
}
```

When `inject headers with claims` is specified, claims from the session will be injected into the request upstream. For example, the `role` claim will be injected as `X-Autentico-Role`, and `email` as `X-Autentico-Email`. The plugin automatically strips incoming headers with this prefix to prevent spoofing.
