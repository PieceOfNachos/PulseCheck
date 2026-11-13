import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { authApi, clearToken, getToken, setToken } from "@/lib/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
  }, []);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    authApi
      .get("/api/auth/me")
      .then((data) => setUser(data.user))
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    window.addEventListener("pulsecheck:unauthorized", logout);
    return () => window.removeEventListener("pulsecheck:unauthorized", logout);
  }, [logout]);

  const login = useCallback(async (email, password) => {
    const data = await authApi.post("/api/auth/login", { email, password });
    setToken(data.token);
    setUser(data.user);
    return data.user;
  }, []);

  const register = useCallback(async (email, password) => {
    const data = await authApi.post("/api/auth/register", {
      email,
      password,
    });
    setToken(data.token);
    setUser(data.user);
    return data.user;
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
