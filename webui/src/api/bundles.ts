import { apiJson, apiFetch, ApiError } from './client';

export interface WindowInfo {
  produced_at: number;
  this_update_min: number;
  next_update_min: number;
  next_update_max: number;
}

export interface BundleInfo {
  ca_label: string;
  epoch: number;
  completeness: string;
  entry_count: number;
  window: WindowInfo | null;
}

export interface BundleDetail {
  ca_label: string;
  epoch: number;
  completeness: string;
}

export interface InspectResult {
  bundle_id: string;
  producer_id: string;
  created_at: number;
  bundle_type: string;
  entry_count: number;
  window: WindowInfo;
  scopes: Array<{
    issuer_name_hash: string;
    issuer_key_hash: string;
    epoch: number;
    completeness: string;
    signature_algorithm: string;
  }>;
  integrity: { index_digest: string; data_digest: string };
  seal_present: boolean;
  index_records: number;
}

export interface VerifyResult {
  header_ok: boolean;
  manifest_ok: boolean;
  index_digest_ok: boolean;
  data_digest_ok: boolean;
  sort_order_ok: boolean;
  entry_bounds_ok: boolean;
  seal_present: boolean;
  entry_count_matches: boolean;
  warnings: string[];
  overall_ok: boolean;
}

export function listBundles(): Promise<{ bundles: BundleInfo[] }> {
  return apiJson('/api/admin/bundles');
}

export function getBundleDetail(label: string): Promise<BundleDetail> {
  return apiJson(`/api/admin/bundles/${encodeURIComponent(label)}`);
}

export function reloadBundles(): Promise<{ status: string; bundle_count: number; total_entries: number }> {
  return apiJson('/api/admin/bundles/reload', { method: 'POST' });
}

export async function inspectBundle(file: File): Promise<InspectResult> {
  const buf = await file.arrayBuffer();
  const resp = await apiFetch('/api/admin/bundles/inspect', {
    method: 'POST',
    body: buf,
    headers: { 'Content-Type': 'application/octet-stream' },
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<InspectResult>;
}

export async function verifyBundle(file: File): Promise<VerifyResult> {
  const buf = await file.arrayBuffer();
  const resp = await apiFetch('/api/admin/bundles/verify', {
    method: 'POST',
    body: buf,
    headers: { 'Content-Type': 'application/octet-stream' },
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<VerifyResult>;
}
