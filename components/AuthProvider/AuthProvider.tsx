"use client";

import { checkSession, getMe } from "@/lib/api/clientApi";
import { useLogin } from "@/lib/store/authStore";
import { useEffect } from "react";

interface AuthStoreProps {
  children: React.ReactNode;
}

export default function AuthStore({ children }: AuthStoreProps) {
  const setUser = useLogin((state) => state.setUser);
  const logout = useLogin((state) => state.clearIsAuthenticated);

  useEffect(() => {
    async function getUser() {
      const isLogin = await checkSession();
      if (isLogin) {
        const user = await getMe();
        if (user) {
          setUser(user);
        }
      } else {
        logout();
      }
    }
    getUser();
  }, [setUser, logout]);

  return children;
}
