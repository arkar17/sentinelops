import { type ReactNode, useCallback, useEffect, useState } from "react";
import { ApiError, apiRequest, type Me } from "./api.ts";
import { AuthContext } from "./auth-context.ts";

async function fetchMe(): Promise<Me | null> {
  try {
    return await apiRequest<Me>("GET", "/api/auth/me");
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 401) {
      console.error("Could not load the current user", error);
    }
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setMe(await fetchMe());
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiRequest("POST", "/api/auth/logout");
    } finally {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    let active = true;
    void fetchMe().then((value) => {
      if (active) {
        setMe(value);
        setLoading(false);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  return (
    <AuthContext.Provider value={{ me, loading, refresh, logout }}>{children}</AuthContext.Provider>
  );
}
