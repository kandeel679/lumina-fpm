import { createContext, useContext, useState, useCallback } from 'react';
import { mockUsers } from '../data/mockUsers';

const AuthContext = createContext(null);

const SESSION_KEY = 'lumina_fpm_user';

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => loadSession());

  const login = useCallback((email, password) => {
    const found = mockUsers.find(
      u => u.email.toLowerCase() === email.toLowerCase() && u.password === password
    );
    if (!found) return { success: false, error: 'Invalid email or password.' };

    const session = { ...found };
    delete session.password;           // never store password
    session.loginAt = new Date().toISOString();

    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    setUser(session);
    return { success: true };
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(SESSION_KEY);
    setUser(null);
  }, []);

  const switchAccount = useCallback((targetUser) => {
    const session = { ...targetUser };
    delete session.password;
    session.loginAt = new Date().toISOString();
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    setUser(session);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout, switchAccount }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
