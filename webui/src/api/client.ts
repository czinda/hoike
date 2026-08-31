const BASE = '';

function getToken(): string | null {
  const raw = sessionStorage.getItem('hoike_auth');
  if (!raw) return null;
  try {
    return (JSON.parse(raw) as { token: string | null }).token;
  } catch {
    sessionStorage.removeItem('hoike_auth');
    return null;
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string>),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (init?.body && typeof init.body === 'string' && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const resp = await fetch(`${BASE}${path}`, { ...init, headers });
  if (resp.status === 401) {
    sessionStorage.removeItem('hoike_auth');
    window.location.href = '/ui/login';
    throw new ApiError(401, 'session expired');
  }
  return resp;
}

function extractErrorMessage(status: number, text: string, statusText: string): string {
  if (text) {
    try {
      const body = JSON.parse(text) as Record<string, unknown>;
      if (typeof body.detail === 'string' && body.detail) {
        const prefix =
          status === 403 ? 'Access denied' :
          status === 404 ? 'Not found' :
          status === 400 ? 'Bad request' :
          status >= 500 ? 'Server error' : null;
        return prefix ? `${prefix}: ${body.detail}` : body.detail;
      }
    } catch {
      // not JSON
    }
    return text;
  }
  return statusText;
}

export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await apiFetch(path, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
  return resp.json() as Promise<T>;
}

export async function apiVoid(path: string, init?: RequestInit): Promise<void> {
  const resp = await apiFetch(path, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, extractErrorMessage(resp.status, text, resp.statusText));
  }
}

export function errorMessage(e: unknown, fallback = 'An error occurred'): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof TypeError && e.message === 'Failed to fetch')
    return 'Network error — check your connection';
  if (e instanceof Error) return e.message;
  return fallback;
}
