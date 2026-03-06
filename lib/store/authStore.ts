import { create } from "zustand";

import { type User } from "@/types/user";

interface IsLogin {
  isAuthenticated: boolean;
  user: User;
  setUser: (user: User) => void;
  clearIsAuthenticated: () => void;
}

const initUser: User = {
  username: "",
  email: "",
  avatar: "",
};

export const useLogin = create<IsLogin>()((set) => ({
  isAuthenticated: false,
  user: initUser,
  setUser: (data) => set(() => ({ user: data, isAuthenticated: true })),
  clearIsAuthenticated: () =>
    set(() => ({ user: initUser, isAuthenticated: false })),
}));
