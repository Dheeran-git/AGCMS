import { create } from 'zustand';

interface AuthState {
  token: string;
  refreshToken: string | null;
  setToken: (token: string) => void;
  setTokens: (access: string, refresh: string) => void;
  clearToken: () => void;
}

const DEFAULT_TOKEN =
  (import.meta.env.VITE_AGCMS_API_KEY as string | undefined) ||
  'agcms_test_key_for_development';

export const useAuthStore = create<AuthState>((set) => ({
  token: DEFAULT_TOKEN,
  refreshToken: null,
  setToken: (token) => set({ token }),
  setTokens: (access, refresh) => set({ token: access, refreshToken: refresh }),
  clearToken: () => set({ token: DEFAULT_TOKEN, refreshToken: null }),
}));
