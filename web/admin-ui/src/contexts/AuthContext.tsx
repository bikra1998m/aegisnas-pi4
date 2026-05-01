import React, { createContext, useState, useContext, useEffect } from 'react';
import api from '../api/client';

interface AuthContextType {
  isAuthenticated: boolean;
  login: (token: string, mode?: 'token' | 'sso') => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(!!localStorage.getItem('token'));

  const login = (token: string, mode: 'token' | 'sso' = 'token') => {
    localStorage.setItem('token', token);
    localStorage.setItem('auth_mode', mode);
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
    setIsAuthenticated(false);
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    setIsAuthenticated(!!token);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
