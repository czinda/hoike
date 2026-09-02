import { apiJson } from './client';

export type MemberState = 'alive' | 'suspect' | 'down';

export interface GossipMember {
  name: string;
  addr: string;
  incarnation: number;
  state: MemberState;
  is_self: boolean;
}

export interface GossipGeneration {
  origin_node: string;
  producer_id: string;
  issuer_key_hash: string;
  epoch: number;
  manifest_digest: string;
  last_seen_unix: number;
  /** Seconds since this announcement was last observed (server-computed). */
  age_secs: number;
  /** How many epochs this node trails the highest epoch seen for its scope. */
  epochs_behind: number;
  stale: boolean;
}

export interface GossipSelf {
  name: string;
  addr: string;
  incarnation: number;
}

export interface GossipStatus {
  enabled: boolean;
  /** True when gossip is enabled in config, even if no live node is attached. */
  configured?: boolean;
  /** Present only when gossip is disabled or not running. */
  message?: string;
  self?: GossipSelf;
  member_count?: number;
  members?: GossipMember[];
  generations?: GossipGeneration[];
}

export function getGossip(): Promise<GossipStatus> {
  return apiJson('/api/admin/gossip');
}
