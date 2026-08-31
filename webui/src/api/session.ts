import { apiJson, apiVoid } from './client';

export interface LoginRequest {
  name: string;
  password: string;
}

export interface LoginResponse {
  session_token: string;
  role: string;
  operator: string;
  expires_in_secs: number;
}

export function login(req: LoginRequest): Promise<LoginResponse> {
  return apiJson('/api/admin/session', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function logout(): Promise<void> {
  try {
    await apiVoid('/api/admin/session', { method: 'DELETE' });
  } catch {
    // best-effort
  }
}
