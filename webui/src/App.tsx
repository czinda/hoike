import React, { Component, type ReactNode, Suspense, useCallback, useMemo } from 'react';
import { Routes, Route, Navigate, NavLink, Outlet, useLocation, Link } from 'react-router-dom';
import {
  Page,
  Masthead,
  MastheadMain,
  MastheadBrand,
  MastheadContent,
  Nav,
  NavList,
  NavItem,
  PageSidebar,
  PageSidebarBody,
  Button,
  Label,
  Flex,
  FlexItem,
  Spinner,
} from '@patternfly/react-core';
import { useAuth } from './auth/AuthContext';
import { logout as apiLogout } from './api/session';
import { NAV_ITEMS, canAccess } from './nav';
import RoleGuard from './auth/RoleGuard';

const LoginPage = React.lazy(() => import('./auth/LoginPage'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Bundles = React.lazy(() => import('./pages/Bundles'));
const BundleDetail = React.lazy(() => import('./pages/Bundles/Detail'));
const BundleInspect = React.lazy(() => import('./pages/Bundles/Inspect'));
const CAs = React.lazy(() => import('./pages/CAs'));
const CADetail = React.lazy(() => import('./pages/CAs/Detail'));
const Signing = React.lazy(() => import('./pages/Signing'));
const Query = React.lazy(() => import('./pages/Query'));
const Gossip = React.lazy(() => import('./pages/Gossip'));
const Config = React.lazy(() => import('./pages/Config'));

class PageErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  override render() {
    if (this.state.error) {
      return (
        <div style={{ padding: '2rem' }}>
          <h2>Something went wrong</h2>
          <p style={{ color: '#c9190b', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
            {this.state.error.message}
          </p>
          <button onClick={() => this.setState({ error: null })}>Try again</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function LocationResetErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <PageErrorBoundary key={pathname}>{children}</PageErrorBoundary>;
}

function NotFound() {
  return (
    <div style={{ textAlign: 'center', padding: '4rem 1rem' }}>
      <h1>404 — Page Not Found</h1>
      <p>The page you requested does not exist.</p>
      <Link to="/">Back to Dashboard</Link>
    </div>
  );
}

function AppHeader({ onLogout }: { onLogout: () => void }) {
  const { role, operatorName } = useAuth();
  return (
    <Masthead>
      <MastheadMain>
        <MastheadBrand>hoike OCSP</MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Flex>
          {role && <FlexItem><Label color="blue">{role}</Label></FlexItem>}
          {operatorName && <FlexItem>{operatorName}</FlexItem>}
          <FlexItem>
            <Button variant="link" onClick={onLogout} style={{ color: '#fff' }}>Logout</Button>
          </FlexItem>
        </Flex>
      </MastheadContent>
    </Masthead>
  );
}

function AppSidebar() {
  const { role } = useAuth();
  return (
    <PageSidebar>
      <PageSidebarBody>
        <Nav>
          <NavList>
            {NAV_ITEMS.filter(item => canAccess(role, item.access)).map(item => (
              <NavItem key={item.path}>
                <NavLink to={item.path} end={item.end}>{item.label}</NavLink>
              </NavItem>
            ))}
          </NavList>
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );
}

const MemoSidebar = React.memo(AppSidebar);
const MemoHeader = React.memo(AppHeader);

function AuthenticatedLayout() {
  const { token, clearAuth } = useAuth();

  const handleLogout = useCallback(async () => {
    await apiLogout();
    clearAuth();
    window.location.href = '/ui/login';
  }, [clearAuth]);

  const masthead = useMemo(() => <MemoHeader onLogout={handleLogout} />, [handleLogout]);
  const sidebar = useMemo(() => <MemoSidebar />, []);

  if (!token) return <Navigate to="/login" replace />;

  return (
    <Page masthead={masthead} sidebar={sidebar} isManagedSidebar>
      <LocationResetErrorBoundary>
        <Suspense fallback={<Spinner />}>
          <Outlet />
        </Suspense>
      </LocationResetErrorBoundary>
    </Page>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Suspense fallback={<Spinner />}><LoginPage /></Suspense>} />
      <Route element={<AuthenticatedLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/bundles" element={<Bundles />} />
        <Route path="/bundles/:label" element={<BundleDetail />} />
        <Route path="/bundles/inspect" element={<BundleInspect />} />
        <Route path="/cas" element={<CAs />} />
        <Route path="/cas/:label" element={<CADetail />} />
        <Route path="/signing" element={
          <RoleGuard minRole="operator"><Signing /></RoleGuard>
        } />
        <Route path="/query" element={<Query />} />
        <Route path="/gossip" element={<Gossip />} />
        <Route path="/config" element={<Config />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
