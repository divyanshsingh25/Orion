import type { PropsWithChildren } from "react";
import { Sidebar } from "@/sidebar/Sidebar";
import { Topbar } from "@/navbar/Topbar";
import { OrionPets } from "@/components/pets/OrionPets";
import { useThemeStore } from "@/hooks/useThemeStore";
import { cn } from "@/utils/cn";

export function AppLayout({ children }: PropsWithChildren) {
  const collapsed = useThemeStore((state) => state.sidebarCollapsed);

  return (
    <div className="page-shell">
      <Sidebar />
      <Topbar />
      <main className={cn("min-h-screen pt-[78px] transition-[margin] duration-300 ease-out", collapsed ? "lg:ml-[88px]" : "lg:ml-[320px]")}> 
        <div className="content-inner">{children}</div>
      </main>
      <OrionPets />
    </div>
  );
}