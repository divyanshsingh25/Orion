import { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  FileText,
  GitCompare,
  Globe2,
  Grid2X2,
  Hexagon,
  LogOut,
  RadioTower,
  ScanLine,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { cn } from "@/utils/cn";
import { useThemeStore } from "@/hooks/useThemeStore";
import { useCurrentUser } from "@/hooks/useCurrentUser";
import { clearAuthTokens, getActiveScan, type ScanDetail } from "@/services/api";

const navItems = [
  { label: "Dashboard", href: "/dashboard", icon: Grid2X2 },
  { label: "New Scan", href: "/new-scan", icon: ScanLine },
  { label: "Live Scan", href: "/live-scan", icon: Activity },
  { label: "Scan History", href: "/scan-history", icon: RadioTower },
  { label: "Vulnerabilities", href: "/vulnerabilities", icon: Shield },
  { label: "Attack Surface", href: "/attack-surface", icon: Globe2 },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Compare", href: "/compare", icon: GitCompare },
  { label: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const navigate = useNavigate();
  const collapsed = useThemeStore((state) => state.sidebarCollapsed);
  const toggleSidebar = useThemeStore((state) => state.toggleSidebar);
  const [showLogout, setShowLogout] = useState(false);
  const { user } = useCurrentUser();

  const displayName = user?.full_name || user?.username || "Security User";
  const displayEmail = user?.email || "user@orion.sec";
  const initials = (() => {
    const raw = (user?.full_name || user?.username || "U").trim();
    const parts = raw.split(/\s+/);
    if (parts.length > 1) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return raw.slice(0, 2).toUpperCase();
  })();

  // Poll backend for active scan status — maintains dynamic status across all pages
  const activeScanQuery = useQuery({
    queryKey: ["active-scan"],
    queryFn: getActiveScan,
    refetchInterval: (query) => {
      const data = query.state.data as ScanDetail | null | undefined;
      const status = data?.status;
      return status === "running" || status === "queued" ? 1500 : 4000;
    },
  });

  const activeScan = activeScanQuery.data;
  const status = activeScan?.status;
  const progress = activeScan?.progress_percent ?? 0;

  let assessmentLabel = "Idle - Sensor Ready";
  let statusTone = "border-cyan-300/15 bg-cyan-300/[0.08] text-cyan-300";
  let isPulse = false;

  if (!activeScan || !status) {
    assessmentLabel = "Idle - Sensor Ready";
  } else if (status === "queued") {
    assessmentLabel = "Scanning / Assessment Active";
    statusTone = "border-cyan-400/25 bg-cyan-400/[0.12] text-cyan-400";
    isPulse = true;
  } else if (status === "running") {
    if (progress <= 1) {
      assessmentLabel = "Scanning / Assessment Active";
    } else {
      assessmentLabel = `Scanning — ${progress}%`;
    }
    statusTone = "border-cyan-400/25 bg-cyan-400/[0.12] text-cyan-400";
    isPulse = true;
  } else if (status === "completed") {
    assessmentLabel = "Scan Complete / Sensor Ready";
    statusTone = "border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-400";
  } else if (status === "failed") {
    assessmentLabel = "Scan Failed";
    statusTone = "border-rose-400/25 bg-rose-400/[0.08] text-rose-400";
  } else if (status === "cancelled") {
    assessmentLabel = "Scan Cancelled / Sensor Ready";
    statusTone = "border-amber-400/20 bg-amber-400/[0.08] text-amber-400";
  }

  return (
    <>
      <motion.aside
        animate={{ width: collapsed ? 88 : 320 }}
        transition={{ duration: 0.28, ease: "easeOut" }}
        className="fixed left-0 top-0 z-40 hidden h-screen overflow-hidden border-r border-white/10 bg-sidebar text-sidebar-foreground shadow-[18px_0_60px_rgba(2,6,23,0.28)] lg:flex lg:flex-col"
      >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_0%,rgba(14,165,233,0.22),transparent_34%),linear-gradient(180deg,rgba(15,23,42,0.2),rgba(2,6,23,0.72))]" />
      <div className="relative flex h-[86px] shrink-0 items-center border-b border-white/10 px-4">
        <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-[14px] bg-gradient-to-br from-cyan-400/20 via-sky-500/20 to-blue-700/20 shadow-[0_14px_32px_rgba(14,165,233,0.15)] overflow-hidden">
          <img src="/orion-logo.png" alt="Orion Logo" className="h-full w-full object-cover scale-110" />
          <span className="absolute -right-1 -top-1 h-3 w-3 rounded-full border-2 border-sidebar bg-emerald-400 z-10" />
        </div>
        <motion.div
          animate={{ opacity: collapsed ? 0 : 1, x: collapsed ? -8 : 0 }}
          transition={{ duration: 0.18 }}
          className={cn("ml-3 min-w-[185px] leading-none", collapsed && "pointer-events-none")}
        >
          <div className="flex items-center gap-2 text-[18px] font-bold tracking-[0.02em]">ORION <Sparkles className="h-3.5 w-3.5 text-cyan-300" /></div>
          <div className="mt-1.5 text-[11px] font-bold uppercase tracking-[0.16em] text-slate-400">AI Security Desk</div>
        </motion.div>
        <button
          type="button"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={toggleSidebar}
          className="ml-auto flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/5 text-slate-300 transition hover:bg-white/10 hover:text-white"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      <nav className="relative flex-1 overflow-y-auto px-3 py-4 custom-scrollbar">
        <div className="space-y-1.5">
          {navItems.map((item) => (
            <NavLink
              key={item.href}
              to={item.href}
              end={item.href === "/"}
              title={collapsed ? item.label : undefined}
              className={({ isActive }) =>
                cn(
                  "group relative flex h-[48px] items-center rounded-[13px] text-[15px] font-bold transition-all duration-200",
                  collapsed ? "justify-center px-0" : "gap-3 px-3.5",
                  isActive
                    ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-[0_14px_34px_rgba(14,165,233,0.28)]"
                    : "text-slate-300 hover:bg-white/[0.07] hover:text-white",
                )
              }
            >
              <item.icon className="h-5 w-5 shrink-0" strokeWidth={2.15} />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}
        </div>
      </nav>

      <div className="relative shrink-0 border-t border-white/10 px-3 pb-4 pt-4">
        <div
          className={cn(
            "mb-3 rounded-[14px] border p-3 transition-all duration-300 cursor-pointer",
            statusTone,
            collapsed && "px-2"
          )}
          onClick={() => navigate(activeScan ? `/live-scan?scanId=${activeScan.id}` : "/live-scan")}
          title={collapsed ? `Assessment: ${assessmentLabel}` : undefined}
        > 
          <div className="flex items-center gap-2">
            <Hexagon className={cn("h-4 w-4", isPulse && "animate-pulse")} />
            {!collapsed && <span className="text-[11px] font-extrabold uppercase tracking-[0.16em]">Assessment</span>}
          </div>
          {!collapsed && <div className="mt-2 text-[15px] font-bold text-white truncate">{assessmentLabel}</div>}
        </div>
        <div 
          className={cn("flex items-center pb-3 cursor-pointer select-none transition-opacity hover:opacity-80", collapsed && "justify-center")}
          onClick={() => setShowLogout(!showLogout)}
        > 
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-sky-400 to-indigo-600 text-[13px] font-bold text-white">
            {initials}
          </div>
          {!collapsed && (
            <div className="ml-3 min-w-0">
              <div className="truncate text-[15px] font-bold text-white">{displayName}</div>
              <div className="truncate text-[13px] font-medium text-slate-400">{displayEmail}</div>
            </div>
          )}
        </div>
        
        {showLogout && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="pt-2 border-t border-white/10"
          >
            <button
              type="button"
              title="Logout"
              onClick={() => {
                clearAuthTokens();
                navigate("/login");
              }}
              className={cn("flex h-[40px] w-full items-center rounded-[12px] text-left text-[14px] font-bold text-slate-300 transition hover:bg-white/[0.07] hover:text-white", collapsed ? "justify-center" : "gap-3 px-3")}
            >
              <LogOut className="h-5 w-5" />
              {!collapsed && "Logout"}
            </button>
          </motion.div>
        )}
      </div>
    </motion.aside>
    {collapsed && (
      <button
        type="button"
        title="Expand sidebar"
        onClick={toggleSidebar}
        className="fixed left-[72px] top-[23px] z-50 hidden h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-slate-950 text-cyan-300 shadow-[0_18px_36px_rgba(2,6,23,0.35)] transition hover:scale-105 hover:bg-cyan-500 hover:text-white lg:flex"
      >
        <ChevronRight className="h-5 w-5" />
      </button>
    )}
    </>
  );
}