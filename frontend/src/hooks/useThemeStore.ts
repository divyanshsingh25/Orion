import { create } from "zustand";

interface ThemeState {
  isDark: boolean;
  sidebarCollapsed: boolean;
  toggleTheme: () => void;
  toggleSidebar: () => void;
  setDark: (isDark: boolean) => void;
}

export const useThemeStore = create<ThemeState>((set) => ({
  isDark: false,
  sidebarCollapsed: false,
  toggleTheme: () => set((state) => ({ isDark: !state.isDark })),
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  setDark: (isDark) => set({ isDark }),
}));