const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.message || body.error || `Request failed (${response.status})`);
  }
  return body;
}

export const api = {
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
