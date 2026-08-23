// This page talks to autentico directly - it runs its own OAuth 2.0
// Authorization Code + PKCE login against the "autentico-account" client
// autentico seeds at bootstrap (pkg/cli/start.go in the autentico repo),
// whose redirect_uri is already this origin + /account/callback. Caddy just
// serves these static files and reverse-proxies /account/api/*, /oauth2/*
// unmodified - it is not part of the auth flow.
const OAUTH_CLIENT_ID = 'autentico-account';
const OAUTH_SCOPE = 'openid profile email offline_access';
const REDIRECT_URI = window.location.origin + '/account/callback';
const POST_LOGOUT_REDIRECT_URI = window.location.origin + '/account/';
const AUTHORIZE_ENDPOINT = '/oauth2/authorize';
const TOKEN_ENDPOINT = '/oauth2/token';
const LOGOUT_ENDPOINT = '/oauth2/logout';

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
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: OAUTH_SCOPE,
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
    redirect_uri: REDIRECT_URI,
    client_id: OAUTH_CLIENT_ID,
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
    client_id: OAUTH_CLIENT_ID,
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
    window.history.replaceState(null, '', '/account/');
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

// fetch() wrapper for /account/api/* calls: attaches the bearer token,
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
    client_id: OAUTH_CLIENT_ID,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
  });
  return `${LOGOUT_ENDPOINT}?${params.toString()}`;
}

function initLogout() {
  const link = document.getElementById('menu-logout');
  if (!link) return;
  link.href = logoutUrl();
  link.addEventListener('click', () => clearTokens());
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

function apiError(json, fallback) {
  return (json && (json.error_description || json.error)) || fallback;
}

function renderApplications(apps) {
  const list = document.getElementById('apps-list');
  if (!apps || apps.length === 0) {
    list.innerHTML = '<p class="auth-text-muted">No applications available.</p>';
    return;
  }
  list.innerHTML = apps.map((app) => {
    const icon = app.icon
      ? `<img class="app-icon" src="${escapeHtml(app.icon)}" alt="" />`
      : `<span class="app-icon app-icon-placeholder">${escapeHtml((app.name || '?').charAt(0).toUpperCase())}</span>`;
    const href = app.url ? escapeHtml(app.url) : '#';
    return `<a class="app-card" href="${href}" target="_blank" rel="noopener noreferrer">${icon}<span class="app-name">${escapeHtml(app.name)}</span></a>`;
  }).join('');
}

async function loadApplications() {
  const list = document.getElementById('apps-list');
  try {
    const res = await apiFetch('/account/api/applications');
    const json = await res.json();
    if (!res.ok) throw new Error(apiError(json, 'Failed to load applications.'));
    renderApplications(json.data || []);
  } catch (e) {
    list.innerHTML = '<p class="auth-error">Failed to load applications.</p>';
  }
}

async function loadProfile() {
  try {
    const res = await apiFetch('/account/api/profile');
    if (!res.ok) return;
    const json = await res.json();
    const user = json.data || {};
    const el = document.getElementById('dash-welcome');
    if (el) el.textContent = `Signed in as ${user.username || user.email || ''}`;
  } catch (e) {
    // non-critical — leave the greeting blank
  }
}

function showBanner(message, isError) {
  const okEl = document.getElementById('dash-banner');
  const errEl = document.getElementById('dash-error');
  okEl.hidden = true;
  errEl.hidden = true;
  const target = isError ? errEl : okEl;
  target.textContent = message;
  target.hidden = false;
}

function initGearMenu() {
  const wrap = document.getElementById('dash-gear');
  const btn = document.getElementById('gear-btn');
  if (!wrap || !btn) return () => {};

  const close = () => {
    wrap.classList.remove('open');
    btn.setAttribute('aria-expanded', 'false');
  };
  const toggle = () => {
    const open = wrap.classList.toggle('open');
    btn.setAttribute('aria-expanded', String(open));
  };

  btn.addEventListener('click', (e) => { e.stopPropagation(); toggle(); });
  document.addEventListener('click', (e) => { if (!wrap.contains(e.target)) close(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

  return close;
}

function initModal(backdropId, onOpen) {
  const backdrop = document.getElementById(backdropId);
  if (!backdrop) return null;
  const open = () => { backdrop.hidden = false; if (onOpen) onOpen(); };
  const close = () => { backdrop.hidden = true; };
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
  backdrop.querySelectorAll('[data-modal-close]').forEach((el) => el.addEventListener('click', close));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !backdrop.hidden) close(); });
  return { open, close };
}

function initPasswordModal(closeGear) {
  const trigger = document.getElementById('menu-password');
  const form = document.getElementById('password-form');
  const errEl = document.getElementById('password-error');
  const modal = initModal('password-modal', () => {
    errEl.hidden = true;
    form.reset();
    document.getElementById('current_password').focus();
  });
  if (!modal || !trigger || !form) return;

  trigger.addEventListener('click', () => { closeGear(); modal.open(); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.hidden = true;
    const current = document.getElementById('current_password').value;
    const next = document.getElementById('new_password').value;
    const confirm = document.getElementById('confirm_new_password').value;
    if (next !== confirm) {
      errEl.textContent = 'New passwords do not match.';
      errEl.hidden = false;
      return;
    }
    try {
      const res = await apiFetch('/account/api/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        errEl.textContent = apiError(json, 'Failed to update password.');
        errEl.hidden = false;
        return;
      }
      modal.close();
      showBanner('Password updated successfully.', false);
    } catch (e2) {
      errEl.textContent = 'Failed to update password.';
      errEl.hidden = false;
    }
  });
}

function initDeleteModal(closeGear) {
  const trigger = document.getElementById('menu-delete');
  const errEl = document.getElementById('delete-error');
  const confirmBtn = document.getElementById('delete-confirm');
  const modal = initModal('delete-modal', () => { errEl.hidden = true; });
  if (!modal || !trigger || !confirmBtn) return;

  trigger.addEventListener('click', () => { closeGear(); modal.open(); });

  confirmBtn.addEventListener('click', async () => {
    errEl.hidden = true;
    confirmBtn.disabled = true;
    try {
      const res = await apiFetch('/account/api/deletion-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.status === 204) {
        clearTokens();
        window.location.href = logoutUrl();
        return;
      }
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        errEl.textContent = apiError(json, 'Failed to request account deletion.');
        errEl.hidden = false;
        return;
      }
      modal.close();
      showBanner('Deletion requested. An administrator will review it.', false);
    } catch (e) {
      errEl.textContent = 'Failed to request account deletion.';
      errEl.hidden = false;
    } finally {
      confirmBtn.disabled = false;
    }
  });
}

const closeGear = initGearMenu();
initPasswordModal(closeGear);
initDeleteModal(closeGear);
initLogout();
ensureAuthenticated().then(() => {
  loadProfile();
  loadApplications();
});
