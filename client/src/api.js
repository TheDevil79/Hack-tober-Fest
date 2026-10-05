const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
const TOKEN_KEY = 'patchlens_session';

function getToken() {
  return window.sessionStorage.getItem(TOKEN_KEY) || '';
}

async function request(path, options = {}) {
  const token = getToken();
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/auth/login') {
      window.sessionStorage.removeItem(TOKEN_KEY);
      window.dispatchEvent(new Event('patchlens:unauthorized'));
    }
    throw new Error(body.message || body.error || `Request failed (${response.status})`);
  }
  return body;
}

export const api = {
  hasSession: () => Boolean(getToken()),
  login: async (username, password) => {
    const session = await request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    window.sessionStorage.setItem(TOKEN_KEY, session.token);
    return session;
  },
  session: () => request('/api/auth/session'),
  logout: () => window.sessionStorage.removeItem(TOKEN_KEY),
  health: () => request('/health'),
  scan: url => request('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ url })
  }),
  history: target => request(`/api/intelligence/history?target=${encodeURIComponent(target)}`),
  getScan: id => request(`/api/intelligence/scans/${encodeURIComponent(id)}`),
  compare: (currentId, previousId) => request('/api/intelligence/compare', {
    method: 'POST',
    body: JSON.stringify({ currentId, previousId })
  })
};
