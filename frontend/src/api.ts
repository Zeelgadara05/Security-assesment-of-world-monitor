export const API_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  'http://127.0.0.1:8001';