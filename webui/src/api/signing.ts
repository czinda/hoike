import { apiJson } from './client';

export interface SignResult {
  status: string;
  ca_label?: string;
  cas?: string[];
  message: string;
}

export interface RotateResult {
  status: string;
  ca_label: string;
  command?: string;
  detail?: string;
}

export interface RotationStatus {
  ca_label: string;
  status: string;
  expires_in_secs: number | null;
  error?: string;
}

export function signCa(label: string): Promise<SignResult> {
  return apiJson(`/api/admin/sign/${encodeURIComponent(label)}`, { method: 'POST' });
}

export function signAll(): Promise<SignResult> {
  return apiJson('/api/admin/sign/all', { method: 'POST' });
}

export function rotateCa(label: string): Promise<RotateResult> {
  return apiJson(`/api/admin/rotate/${encodeURIComponent(label)}`, { method: 'POST' });
}

export function getRotation(): Promise<{ rotation: RotationStatus[] }> {
  return apiJson('/api/admin/rotation');
}
