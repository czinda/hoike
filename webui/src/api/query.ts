import { apiJson } from './client';
import type { WindowInfo } from './bundles';

export interface QueryRequest {
  serial: string;
  issuer_name_hash: string;
  issuer_key_hash: string;
  prefer?: string[];
}

export interface QueryResult {
  found: boolean;
  ca_label?: string;
  response_bytes_len?: number;
  nonce_policy?: string;
  window?: WindowInfo;
  message?: string;
}

export function queryOcsp(req: QueryRequest): Promise<QueryResult> {
  return apiJson('/api/admin/query', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}
