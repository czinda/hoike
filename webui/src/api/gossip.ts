import { apiJson } from './client';

export interface GossipStatus {
  enabled: boolean;
  message: string;
}

export function getGossip(): Promise<GossipStatus> {
  return apiJson('/api/admin/gossip');
}
