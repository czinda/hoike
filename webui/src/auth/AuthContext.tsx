import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import type { Role } from '../nav';

interface AuthState {
  token: string | null;
  role: Role | null;
  operatorName: string | null;
  expiresAt: number | null;
}

interface AuthContextValue extends AuthState {
  setAuth: (token: string, role: Role, operatorName: string, expiresInSecs: number) => void;
  clearAuth: () => void;
}

const STORAGE_KEY = 'hoike_auth';

const AuthContext = createContext<AuthContextValue | null>(null);

function loadFromStorage(): AuthState {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { token: null, role: null, operatorName: null, expiresAt: null };
    return JSON.parse(raw) as AuthState;
  } catch {
    sessionStorage.removeItem(STORAGE_KEY);
    return { token: null, role: null, operatorName: null, expiresAt: null };
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuthState] = useState<AuthState>(loadFromStorage);

  const setAuth = useCallback((token: string, role: Role, operatorName: string, expiresInSecs: number) => {
    const expiresAt = Date.now() + expiresInSecs * 1000;
    const state: AuthState = { token, role, operatorName, expiresAt };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    setAuthState(state);
  }, []);

  const clearAuth = useCallback(() => {
    sessionStorage.removeItem(STORAGE_KEY);
    setAuthState({ token: null, role: null, operatorName: null, expiresAt: null });
  }, []);

  useEffect(() => {
    if (!auth.expiresAt) return;
    const remaining = auth.expiresAt - Date.now();
    if (remaining <= 0) {
      clearAuth();
      return;
    }
    const timer = setTimeout(clearAuth, remaining);
    return () => clearTimeout(timer);
  }, [auth.expiresAt, clearAuth]);

  return (
    <AuthContext.Provider value={{ ...auth, setAuth, clearAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
