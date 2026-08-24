// Generic OAuth 2.0 Authorization Code + PKCE client for static account
// pages served outside the autentico binary (e.g. themes/*/account). Those
// pages reverse-proxy /oauth2/* (or wherever AUTENTICO_APP_OAUTH_PATH points)
// straight through to an autentico instance and import this ES module to
// talk to it directly — see themes/retro/account/dashboard.js for a full
// integration example.
//
// Usage:
//   import { createAutenticoAuth } from '/oauth2/static/oidc.js';
//   const auth = createAutenticoAuth({
//     clientId: 'autentico-account',
//     scope: 'openid profile email offline_access',
//     oauthPath: '/oauth2',
//     redirectUri: window.location.origin + '/account/callback',
//     postLogoutRedirectUri: window.location.origin + '/account/',
//   });
//   await auth.ensureAuthenticated();
//   const res = await auth.apiFetch('/account/api/profile');
export function createAutenticoAuth({ clientId, scope, oauthPath = '/oauth2', redirectUri, postLogoutRedirectUri }) {
  const AUTHORIZE_ENDPOINT = oauthPath + '/authorize';
  const TOKEN_ENDPOINT = oauthPath + '/token';
  const LOGOUT_ENDPOINT = oauthPath + '/logout';

  const SS_ACCESS = 'autentico_access_token';
  const SS_REFRESH = 'autentico_refresh_token';
  const SS_EXPIRES = 'autentico_expires_at';
  const SS_VERIFIER = 'autentico_pkce_verifier';
  const SS_STATE = 'autentico_pkce_state';

  function base64UrlEncode(bytes) {
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomBase64Url(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  async function sha256Base64Url(input) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return base64UrlEncode(new Uint8Array(digest));
  }

  function storeTokens(tokens) {
    sessionStorage.setItem(SS_ACCESS, tokens.access_token);
    sessionStorage.setItem(SS_EXPIRES, String(Date.now() + tokens.expires_in * 1000));
    if (tokens.refresh_token) sessionStorage.setItem(SS_REFRESH, tokens.refresh_token);
  }

  function clearTokens() {
    sessionStorage.removeItem(SS_ACCESS);
    sessionStorage.removeItem(SS_REFRESH);
    sessionStorage.removeItem(SS_EXPIRES);
    sessionStorage.removeItem(SS_VERIFIER);
    sessionStorage.removeItem(SS_STATE);
  }

  // Returns the cached access token, or null if missing/expired (with a 5s
  // buffer for clock skew between this call and the actual request landing).
  function getStoredAccessToken() {
    const token = sessionStorage.getItem(SS_ACCESS);
    const expiresAt = Number(sessionStorage.getItem(SS_EXPIRES) || 0);
    if (!token || Date.now() >= expiresAt - 5000) return null;
    return token;
  }

  async function beginLogin() {
    const verifier = randomBase64Url(32);
    const state = randomBase64Url(16);
    const challenge = await sha256Base64Url(verifier);
    sessionStorage.setItem(SS_VERIFIER, verifier);
    sessionStorage.setItem(SS_STATE, state);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    window.location.assign(`${AUTHORIZE_ENDPOINT}?${params.toString()}`);
  }

  async function exchangeCode(code) {
    const verifier = sessionStorage.getItem(SS_VERIFIER) || '';
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const res = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) throw new Error('token exchange failed');
    storeTokens(await res.json());
  }

  async function refreshAccessToken() {
    const refreshToken = sessionStorage.getItem(SS_REFRESH);
    if (!refreshToken) return false;
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    });
    const res = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) return false;
    storeTokens(await res.json());
    return true;
  }

  // Runs once at page load: completes the PKCE round trip if we just landed
  // back from /oauth2/authorize (?code=&state=), otherwise reuses a cached
  // token, refreshes it, or redirects to login as a last resort. beginLogin()
  // navigates away, so callers that reach it never get a return value back.
  async function ensureAuthenticated() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');

    if (code) {
      const expectedState = sessionStorage.getItem(SS_STATE);
      const returnedState = params.get('state');
      window.history.replaceState(null, '', window.location.pathname);
      if (returnedState && returnedState === expectedState) {
        try {
          await exchangeCode(code);
          sessionStorage.removeItem(SS_VERIFIER);
          sessionStorage.removeItem(SS_STATE);
          return getStoredAccessToken();
        } catch (e) {
          clearTokens();
        }
      }
    }

    const existing = getStoredAccessToken();
    if (existing) return existing;

    if (await refreshAccessToken()) return getStoredAccessToken();

    await beginLogin();
    return null;
  }

  // fetch() wrapper for authenticated API calls: attaches the bearer token,
  // obtaining/refreshing one first if needed, and retries once on a 401
  // (access token expired mid-session) before falling back to a fresh login.
  async function apiFetch(path, options = {}) {
    let token = getStoredAccessToken();
    if (!token) token = await ensureAuthenticated();

    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    let res = await fetch(path, { ...options, headers });

    if (res.status === 401) {
      if (await refreshAccessToken()) {
        headers.set('Authorization', `Bearer ${getStoredAccessToken()}`);
        res = await fetch(path, { ...options, headers });
      } else {
        clearTokens();
        await beginLogin();
      }
    }
    return res;
  }

  function logoutUrl() {
    const params = new URLSearchParams({
      client_id: clientId,
      post_logout_redirect_uri: postLogoutRedirectUri,
    });
    return `${LOGOUT_ENDPOINT}?${params.toString()}`;
  }

  return { ensureAuthenticated, apiFetch, logoutUrl, clearTokens, getStoredAccessToken };
}
