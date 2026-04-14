import { create } from 'zustand';

interface AuthState {
  token: string;
  setToken: (token: string) => void;
  clearToken: () => void;
}

const DEFAULT_TOKEN =
  (import.meta.env.VITE_AGCMS_API_KEY as string | undefined) ||
  'agcms_test_key_for_development';

export const useAuthStore = create<AuthState>((set) => ({
  token: DEFAULT_TOKEN,
  setToken: (token) => set({ token }),
  clearToken: () => set({ token: DEFAULT_TOKEN }),
}));
