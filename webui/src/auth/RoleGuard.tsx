import { Navigate } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { hasRole, type Role } from '../nav';

interface RoleGuardProps {
  minRole: Role;
  children: React.ReactElement;
}

export default function RoleGuard({ minRole, children }: RoleGuardProps) {
  const { role } = useAuth();
  if (!hasRole(role, minRole)) return <Navigate to="/" replace />;
  return children;
}
