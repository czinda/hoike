import { apiJson } from './client';

export interface CertInfo {
  ca_label: string;
  subject: string;
  issuer: string;
  not_before: number;
  not_after: number;
  is_expired: boolean;
  days_remaining: number;
  has_ocsp_signing_eku: boolean;
}

export function listCerts(): Promise<{ certs: CertInfo[] }> {
  return apiJson('/api/admin/certs');
}
