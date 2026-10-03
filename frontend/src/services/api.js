const cache = new Map();
const CACHE_TTL = 5000;

export function clearApiCache() {
  cache.clear();
}

export async function apiFetch(path, opts = {}) {
  const method = String(opts.method || 'GET').toUpperCase();
  const key = method + ' ' + path;

  if (method === 'GET') {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.time < CACHE_TTL) return hit.data;
  }

  const response = await fetch(path, {
    ...opts,
    credentials: 'include',
    headers: {
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
      ...(opts.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw Object.assign(new Error(data.error || 'Request failed'), { status: response.status });
  }

  if (method === 'GET') cache.set(key, { time: Date.now(), data });
  else clearApiCache();

  return data;
}
