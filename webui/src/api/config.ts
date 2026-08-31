import { apiJson } from './client';

export interface CaConfigInfo {
  label: string;
  nonce_policy: string;
  completeness: string;
  sig_alg: string;
  batch_interval: number;
  validity_secs: number;
  has_signing_key: boolean;
  has_responder_cert: boolean;
  has_seal_key: boolean;
  source_type: string | null;
}

export interface ConfigResponse {
  server: { mode: string; listen: string; max_request: number };
  storage: {
    bundle_dir: string;
    state_db: string;
    max_chain: number;
    seal_trust_anchors: string[] | null;
  };
  cas: CaConfigInfo[];
  gossip: { enabled: boolean; bind: string; seeds: string[]; node_name: string } | null;
}

export interface GossipStatus {
  enabled: boolean;
  message: string;
}

export function getConfig(): Promise<ConfigResponse> {
  return apiJson('/api/admin/config');
}

export function getGossip(): Promise<GossipStatus> {
  return apiJson('/api/admin/gossip');
}

export function getState(): Promise<Record<string, unknown>> {
  return apiJson('/api/admin/state');
}
