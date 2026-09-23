import { Bell, Command, Moon, Search, Sun } from "lucide-react";
import { useClock } from "@/hooks/useClock";
import { useThemeStore } from "@/hooks/useThemeStore";
import { cn } from "@/utils/cn";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

export function Topbar() {
  const { time, date } = useClock();
  const isDark = useThemeStore((state) => state.isDark);
  const collapsed = useThemeStore((state) => state.sidebarCollapsed);
  const toggleTheme = useThemeStore((state) => state.toggleTheme);
  const navigate = useNavigate();

  const [query, setQuery] = useState("");

  return (
    <header className={cn("fixed left-0 top-0 z-30 flex h-[78px] w-full items-center border-b border-white/60 bg-background/[0.78] px-5 backdrop-blur-xl transition-[left,width] duration-300 dark:border-white/10 dark:bg-background/[0.72] lg:w-auto lg:right-0", collapsed ? "lg:left-[88px]" : "lg:left-[320px]")}> 
      <div className="relative h-[46px] w-[580px] max-w-[42vw]">
        <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
        <input
          aria-label="Search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && query.trim()) {
                navigate(`/reports?search=${encodeURIComponent(query.trim())}`);
                setQuery('');
            }
          }}
          className="h-full w-full rounded-[14px] border border-white/70 bg-white/80 pl-[50px] pr-24 text-[15px] font-semibold text-foreground shadow-[0_12px_28px_rgba(15,23,42,0.08)] outline-none backdrop-blur placeholder:text-muted-foreground focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 dark:border-white/10 dark:bg-white/[0.055]"
          placeholder="Search assets, CVEs, endpoints, reports..."
        />
        {query.trim() && (
          <div className="absolute top-[52px] z-50 w-full rounded-[14px] border border-border bg-card p-1.5 shadow-xl">
             <button 
                className="w-full text-left p-2.5 hover:bg-muted/80 rounded-lg text-[13px] font-medium flex items-center justify-between group transition-colors"
                onClick={() => {
                    navigate(`/reports?search=${encodeURIComponent(query.trim())}`);
                    setQuery('');
                }}
             >
                <span className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-cyan-500" />
                  <span>Search reports for <strong className="text-foreground font-semibold">"{query.trim()}"</strong></span>
                </span>
                <span className="text-[11px] font-mono text-muted-foreground group-hover:text-foreground">Reports</span>
             </button>
             <button 
                className="w-full text-left p-2.5 hover:bg-muted/80 rounded-lg text-[13px] font-medium flex items-center justify-between group transition-colors"
                onClick={() => {
                    navigate(`/vulnerabilities?search=${encodeURIComponent(query.trim())}`);
                    setQuery('');
                }}
             >
                <span className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-rose-500" />
                  <span>Search vulnerabilities for <strong className="text-foreground font-semibold">"{query.trim()}"</strong></span>
                </span>
                <span className="text-[11px] font-mono text-muted-foreground group-hover:text-foreground">Findings</span>
             </button>
             <button 
                className="w-full text-left p-2.5 hover:bg-muted/80 rounded-lg text-[13px] font-medium flex items-center justify-between group transition-colors"
                onClick={() => {
                    navigate(`/scan-history?search=${encodeURIComponent(query.trim())}`);
                    setQuery('');
                }}
             >
                <span className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-amber-500" />
                  <span>Search scan history for <strong className="text-foreground font-semibold">"{query.trim()}"</strong></span>
                </span>
                <span className="text-[11px] font-mono text-muted-foreground group-hover:text-foreground">Scans</span>
             </button>
          </div>
        )}
        <div className="absolute right-2 top-1/2 flex h-8 -translate-y-1/2 items-center gap-1 rounded-[10px] border border-border/70 bg-background/70 px-2 text-[12px] font-bold text-muted-foreground">
          <Command className="h-3.5 w-3.5" /> K
        </div>
      </div>

      <div className="ml-auto flex h-full items-center gap-4">
        <div className="hidden items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-3 py-2 text-[13px] font-bold text-emerald-500 xl:flex">
          <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_16px_rgba(52,211,153,0.85)]" /> SOC Online
        </div>
        <button type="button" onClick={toggleTheme} className="flex h-10 items-center gap-2 rounded-full border border-border/70 bg-card/70 px-3 text-[14px] font-bold shadow-[0_10px_25px_rgba(15,23,42,0.06)] transition hover:border-cyan-300 hover:text-cyan-500">
          {isDark ? <Sun className="h-[18px] w-[18px]" /> : <Moon className="h-[18px] w-[18px]" />}
          <span>{isDark ? "Light Mode" : "Dark Mode"}</span>
        </button>
        <div className="relative flex h-10 w-10 items-center justify-center rounded-full border border-border/70 bg-card/70 shadow-[0_10px_25px_rgba(15,23,42,0.06)]">
          <Bell className="h-5 w-5" />
          <span className="absolute -right-1 -top-1 flex h-[20px] min-w-[20px] items-center justify-center rounded-full bg-rose-500 px-1 text-[11px] font-bold text-white">3</span>
        </div>
        <div id="pet-home-mount" className="flex items-center" />
        <div className="h-[42px] w-px bg-border" />
        <div className="min-w-[100px] text-right">
          <div className="font-mono text-[20px] font-bold tracking-[0.04em]">{time}</div>
          <div className="text-[11px] font-extrabold uppercase tracking-[0.08em] text-muted-foreground">{date}</div>
        </div>
      </div>
    </header>
  );
}