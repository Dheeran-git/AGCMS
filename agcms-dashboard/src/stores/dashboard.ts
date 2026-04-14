import { create } from 'zustand';

interface DashboardState {
  activePage: 'overview' | 'violations' | 'playground';
  sidebarOpen: boolean;
  setActivePage: (page: 'overview' | 'violations' | 'playground') => void;
  toggleSidebar: () => void;
}

export const useDashboardStore = create<DashboardState>((set) => ({
  activePage: 'overview',
  sidebarOpen: true,
  setActivePage: (page) => set({ activePage: page }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
}));
