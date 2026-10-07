import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, fetchCsrfToken, clearCsrfToken, onUnauthenticated } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Fetch currently authenticated user profile from /api/auth/me
  const refreshUser = useCallback(async () => {
    try {
      const res = await api.get("/auth/me");
      setUser(res.data?.user || null);
      return res.data?.user || null;
    } catch (err) {
      setUser(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Initialize auth state and CSRF token on startup
  useEffect(() => {
    let isMounted = true;
    (async () => {
      try {
        await fetchCsrfToken();
      } catch {
        // Handled on first request if failed
      }
      if (isMounted) {
        await refreshUser();
      }
    })();

    // Listen for 401 events from background requests
    const unsubscribe = onUnauthenticated(() => {
      setUser(null);
    });

    return () => {
      isMounted = false;
      unsubscribe();
    };
  }, [refreshUser]);

  // Login handler
  const login = async (email, password) => {
    const res = await api.post("/auth/login", { email, password });
    // Invalidate cached token and refetch since session was regenerated (P8)
    clearCsrfToken();
    await fetchCsrfToken(true);
    // Fetch user details including is_admin
    const profile = await refreshUser();
    return profile || res.data?.user;
  };

  // Register handler (does not auto-login per P3)
  const register = async (name, email, password) => {
    const res = await api.post("/auth/register", { name, email, password });
    // Invalidate CSRF token after registration
    clearCsrfToken();
    await fetchCsrfToken(true);
    return res.data;
  };

  // Logout handler (clears state even if request fails)
  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Best-effort logout
    } finally {
      setUser(null);
      clearCsrfToken();
      await fetchCsrfToken(true);
    }
  };

  const value = {
    user,
    loading,
    isAuthenticated: Boolean(user),
    isAdmin: Boolean(user?.is_admin),
    login,
    register,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
