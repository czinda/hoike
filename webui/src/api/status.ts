import { apiJson } from './client';

export interface ServerStatus {
  version: string;
  mode: string;
  listen: string;
  uptime_secs: number;
  bundle_count: number;
  total_entries: number;
  scope_count: number;
}

export function getStatus(): Promise<ServerStatus> {
  return apiJson('/api/admin/status');
}
