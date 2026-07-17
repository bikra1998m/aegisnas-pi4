import React, { createContext, useState, useContext, useEffect } from 'react';
import api from '../api/client';

export type AuthIdentity = {
  subject: string;
  display_name?: string;
  role: string;
  source: string;
  tenants?: string[];
  permissions: string[];
  break_glass: boolean;
};

interface AuthContextType {
  isAuthenticated: boolean;
  identity: AuthIdentity | null;
  login: (token: string, mode?: 'token' | 'sso' | 'webauthn') => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(!!localStorage.getItem('token'));
  const [identity, setIdentity] = useState<AuthIdentity | null>(null);

  const hydrateIdentity = async (token: string) => {
    const { data } = await api.get('/auth/validate', { headers: { Authorization: `Bearer ${token}` } });
    setIdentity(data?.identity || null);
  };

  const login = async (token: string, mode: 'token' | 'sso' | 'webauthn' = 'token') => {
    localStorage.setItem('token', token);
    localStorage.setItem('auth_mode', mode);
    await hydrateIdentity(token);
    setIsAuthenticated(true);
  };

  const logout = async () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        await api.post('/auth/logout', {}, { headers: { Authorization: `Bearer ${token}` } });
      } catch {
        // Local cleanup still matters even when the server-side session is already gone.
      }
    }
    localStorage.removeItem('auth_mode');
    localStorage.removeItem('token');
    setIdentity(null);
    setIsAuthenticated(false);
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    setIsAuthenticated(!!token);
    if (!token) {
      setIdentity(null);
      return;
    }
    hydrateIdentity(token).catch(() => {
      localStorage.removeItem('auth_mode');
      localStorage.removeItem('token');
      setIdentity(null);
      setIsAuthenticated(false);
    });
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, identity, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
