export const API_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  'http://127.0.0.1:8001';

const TOKEN_KEY = 'cyberagent_token';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

export function onUnauthorized(handler: UnauthorizedHandler): void {
  unauthorizedHandler = handler;
}

function notifyUnauthorized(): void {
  clearToken();
  if (unauthorizedHandler) {
    unauthorizedHandler();
  }
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (res.status === 401) {
    notifyUnauthorized();
  }
  return res;
}

export function authUrl(path: string): string {
  const token = getToken();
  const sep = path.includes('?') ? '&' : '?';
  return `${API_URL}${path}${sep}token=${encodeURIComponent(token || '')}`;
}