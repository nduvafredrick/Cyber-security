import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { apiFetch } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const data = await apiFetch('/api/auth/me');
      setUser(data.user || null);
      setOrganization(data.organization || null);
      return data;
    } catch (error) {
      setUser(null);
      setOrganization(null);
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (payload) => {
    const data = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    setUser(data.user || null);
    setOrganization(data.organization || null);
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } finally {
      setUser(null);
      setOrganization(null);
    }
  }, []);

  useEffect(() => {
    refreshUser().catch(() => {});
  }, [refreshUser]);

  const value = useMemo(() => ({
    user,
    organization,
    loading,
    login,
    logout,
    refreshUser,
    setUser,
    setOrganization
  }), [user, organization, loading, login, logout, refreshUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return context;
}
