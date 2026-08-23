// This page talks to autentico directly - it runs its own OAuth 2.0
// Authorization Code + PKCE login against the "autentico-account" client
// autentico seeds at bootstrap (pkg/cli/start.go in the autentico repo),
// whose redirect_uri is already this origin + /account/callback. Caddy just
// serves these static files and reverse-proxies /account/api/*, /oauth2/*
// unmodified - it is not part of the auth flow. The PKCE flow itself lives
// in /oauth2/static/oidc.js, imported below as an ES module, so every
// account theme shares one implementation instead of rolling its own.
import { createAutenticoAuth } from '/oauth2/static/oidc.js';

const auth = createAutenticoAuth({
  clientId: 'autentico-account',
  scope: 'openid profile email offline_access',
  oauthPath: '/oauth2',
  redirectUri: window.location.origin + '/account/callback',
  postLogoutRedirectUri: window.location.origin + '/account/',
});

function initLogout() {
  const link = document.getElementById('menu-logout');
  if (!link) return;
  link.href = auth.logoutUrl();
  link.addEventListener('click', () => auth.clearTokens());
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
    const res = await auth.apiFetch('/account/api/applications');
    const json = await res.json();
    if (!res.ok) throw new Error(apiError(json, 'Failed to load applications.'));
    renderApplications(json.data || []);
  } catch (e) {
    list.innerHTML = '<p class="auth-error">Failed to load applications.</p>';
  }
}

async function loadProfile() {
  try {
    const res = await auth.apiFetch('/account/api/profile');
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
      const res = await auth.apiFetch('/account/api/password', {
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
      const res = await auth.apiFetch('/account/api/deletion-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.status === 204) {
        auth.clearTokens();
        window.location.href = auth.logoutUrl();
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
auth.ensureAuthenticated().then(() => {
  loadProfile();
  loadApplications();
});
