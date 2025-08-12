import { API_BASE } from './config';

type Options = {
  method?: string;
  headers?: Record<string, string>;
  body?: any;
};

export async function api(path: string, opts: Options = {}) {
  const res = await fetch(`${API_BASE}/api${path}`, {
    method: opts.method ?? 'GET',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'include',         // <- send/receive auth cookie
  });

  // Try to parse JSON; if not JSON, throw a readable error
  const text = await res.text();
  try {
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) throw json;
    return json;
  } catch {
    if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
    return {} as any;
  }
}
