export type Role = 'administrator' | 'operator' | 'viewer';

export type RouteAccess = 'public' | { minRole: Role };

export interface NavItem {
  path: string;
  label: string;
  access: RouteAccess;
  end?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { path: '/', label: 'Dashboard', access: { minRole: 'viewer' }, end: true },
  { path: '/bundles', label: 'Bundles', access: { minRole: 'viewer' } },
  { path: '/cas', label: 'CAs', access: { minRole: 'viewer' } },
  { path: '/signing', label: 'Signing', access: { minRole: 'operator' } },
  { path: '/query', label: 'Query', access: { minRole: 'viewer' } },
  { path: '/gossip', label: 'Gossip', access: { minRole: 'viewer' } },
  { path: '/config', label: 'Config', access: { minRole: 'viewer' } },
];

const ROLE_RANK: Record<Role, number> = {
  viewer: 1,
  operator: 2,
  administrator: 3,
};

export function roleRank(role: Role): number {
  return ROLE_RANK[role] ?? 0;
}

export function hasRole(current: Role | null, min: Role): boolean {
  if (!current) return false;
  return roleRank(current) >= roleRank(min);
}

export function canAccess(role: Role | null, access: RouteAccess): boolean {
  if (access === 'public') return true;
  if (!role) return false;
  return hasRole(role, access.minRole);
}
