import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

export interface Identity {
  tenant_id: string;
  user_id: string;
  role: string;
}

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  identity: Identity | null;
  setSession: (access: string, refresh: string | null, identity: Identity) => void;
  setAccessToken: (access: string) => void;
  signOut: () => void;
}

/** Session lives in sessionStorage: it survives reloads but not closing the tab. */
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      refreshToken: null,
      identity: null,
      setSession: (token, refreshToken, identity) => set({ token, refreshToken, identity }),
      setAccessToken: (token) => set({ token }),
      signOut: () => set({ token: null, refreshToken: null, identity: null }),
    }),
    { name: 'agcms-session', storage: createJSONStorage(() => sessionStorage) },
  ),
);
