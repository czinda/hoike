import { apiJson, apiFetch, ApiError } from './client';

/// Encode a File's bytes as standard base64. Chunked to avoid blowing the call
/// stack on large buffers (String.fromCharCode(...spread) caps out around 100k args).
async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export interface WindowInfo {
  produced_at: number;
  this_update_min: number;
  next_update_min: number;
  next_update_max: number;
}

export interface BundleInfo {
  ca_label: string;
  producer_id: string;
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

export interface EntryRef {
  entry_key: string;
  discriminator: number;
}

export interface DiffResult {
  a_entry_count: number;
  b_entry_count: number;
  a_epochs: number[];
  b_epochs: number[];
  added: EntryRef[];
  removed: EntryRef[];
  changed: EntryRef[];
  unchanged: number;
}

export async function diffBundles(a: File, b: File): Promise<DiffResult> {
  const [aB64, bB64] = await Promise.all([fileToBase64(a), fileToBase64(b)]);
  return apiJson('/api/admin/bundles/diff', {
    method: 'POST',
    body: JSON.stringify({ a: aB64, b: bB64 }),
  });
}

export interface ExtractResult {
  found: boolean;
  length: number;
  response_b64: string | null;
}

export async function extractEntry(file: File, certid: string): Promise<ExtractResult> {
  const buf = await file.arrayBuffer();
  const resp = await apiFetch(`/api/admin/bundles/extract?certid=${encodeURIComponent(certid)}`, {
    method: 'POST',
    body: buf,
    headers: { 'Content-Type': 'application/octet-stream' },
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(resp.status, text || resp.statusText);
  }
  return resp.json() as Promise<ExtractResult>;
}

export interface DeltaStat {
  added: number;
  replaced: number;
  removed: number;
  chain_length_warning: boolean;
}

export interface ApplyResult {
  entry_count: number;
  final_epoch: number;
  byte_length: number;
  deltas: DeltaStat[];
  bundle_b64: string;
}

export async function applyDeltas(base: File, deltas: File[]): Promise<ApplyResult> {
  const [baseB64, ...deltasB64] = await Promise.all([
    fileToBase64(base),
    ...deltas.map(fileToBase64),
  ]);
  return apiJson('/api/admin/bundles/apply', {
    method: 'POST',
    body: JSON.stringify({ base: baseB64, deltas: deltasB64 }),
  });
}
