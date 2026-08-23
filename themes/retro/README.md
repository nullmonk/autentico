# Retro theme

A terminal/BBS-styled theme for Autentico's auth pages and account dashboard:
monospace type (IBM Plex Mono), square corners, a green-on-dark/light
terminal palette, and flat CRT scanlines over the page. It's meant to read
like an old HTML-only site — no particle canvas, no blinking cursor, nothing
animated — while still running Autentico's real, modern OAuth2/OIDC flow
underneath (Authorization Code + PKCE, refresh tokens, MFA, etc.).

## Enabling it

Autentico reads theme and template overrides from a single directory,
`AUTENTICO_TEMPLATES_DIR`. Point it at this folder:

```
AUTENTICO_TEMPLATES_DIR=/path/to/themes/retro
```

With that set, two independent override mechanisms pick the files up:

- **Auth pages** (login, signup, MFA, consent, etc.): `static/theme.css` is
  served at `{oauthPath}/static/theme.css` and loaded by every auth page
  after the base `auth.css`, so it only needs to override CSS custom
  properties and add a few retro touches (see
  [view/template.go](../../view/template.go)'s `resolveThemeCSS`).
  `static/logo.svg` overrides the default logo the same way.
- **Account dashboard**: `account/` is served in place of the built-in React
  account UI when `TemplatesDir/account/index.html` exists (see
  [pkg/account/embed.go](../../pkg/account/embed.go)). It's a small static
  HTML/CSS/JS dashboard, not a build step — edit the files directly.

Both overrides are read from disk on each request, so changes are picked up
without restarting the server.

## The dashboard

`account/index.html` + `dashboard.js` + `dashboard.css` implement the same
account features as the default React UI, minus the build tooling:

- Signed-in-as greeting and a grid of the user's available applications
  (`GET /account/api/applications`)
- A gear menu for changing password, logging out, and requesting account
  deletion, each backed by the matching `/account/api/*` endpoint
- Plain `<dialog>`-style modals for the password-change and delete-account
  confirmations — no JS framework

Auth itself doesn't touch Caddy or any proxy logic — `dashboard.js` runs a
real OAuth 2.0 Authorization Code + PKCE flow directly against the autentico
instance, using the shared client at
[`/oauth2/static/oidc.js`](../../view/static/oidc.js) (`createAutenticoAuth`)
that every static account theme imports as an ES module rather than
reimplementing PKCE itself. It authenticates as the `autentico-account`
OAuth2 client that autentico seeds automatically at startup
(`pkg/cli/start.go`), whose redirect URI is already `<origin>/account/callback`.

If `AUTENTICO_APP_OAUTH_PATH` is changed from the default `/oauth2`, update
the `oauthPath` passed to `createAutenticoAuth` in `dashboard.js` to match.
