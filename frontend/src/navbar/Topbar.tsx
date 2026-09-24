import {
  Bell,
  CheckCheck,
  ChevronRight,
  Command,
  FileText,
  Mail,
  Moon,
  Search,
  Sun,
} from "lucide-react";
import { useClock } from "@/hooks/useClock";
import { useThemeStore } from "@/hooks/useThemeStore";
import { cn } from "@/utils/cn";
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  type AppNotification,
  getNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "@/services/api";

function formatRelativeTime(dateString: string): string {
  try {
    const date = new Date(dateString);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (isNaN(diffSec) || diffSec < 45) return "Just now";
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  } catch {
    return "";
  }
}

export function Topbar() {
  const { time, date } = useClock();
  const isDark = useThemeStore((state) => state.isDark);
  const collapsed = useThemeStore((state) => state.sidebarCollapsed);
  const toggleTheme = useThemeStore((state) => state.toggleTheme);
  const navigate = useNavigate();

  const [query, setQuery] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const notifRef = useRef<HTMLDivElement>(null);

  const fetchNotifications = useCallback(async () => {
    try {
      const data = await getNotifications(30);
      // Strictly show ONLY sent report notifications; never show OTP or verification messages
      const reportOnlyItems = (data.items || []).filter((n) => {
        const kindLower = (n.kind || "").toLowerCase();
        const titleLower = (n.title || "").toLowerCase();
        const msgLower = (n.message || "").toLowerCase();

        const isAuthOrOtp =
          kindLower.includes("verification") ||
          kindLower.includes("password") ||
          kindLower.includes("auth") ||
          titleLower.includes("otp") ||
          titleLower.includes("verification") ||
          titleLower.includes("password") ||
          msgLower.includes("one-time passcode") ||
          msgLower.includes("passcode") ||
          msgLower.includes("otp");

        const isReport =
          kindLower.includes("report") ||
          titleLower.includes("report") ||
          msgLower.includes("report");

        return !isAuthOrOtp && isReport;
      });

      setNotifications(reportOnlyItems);
      const unread = reportOnlyItems.filter((n) => !n.read_at).length;
      setUnreadCount(unread);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 12000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    }
    if (showNotifications) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [showNotifications]);

  const handleMarkAllRead = async () => {
    await markAllNotificationsRead();
    setUnreadCount(0);
    setNotifications((prev) =>
      prev.map((n) => ({ ...n, read_at: n.read_at || new Date().toISOString() }))
    );
  };

  const handleNotificationClick = async (notif: AppNotification) => {
    if (!notif.read_at) {
      await markNotificationRead(notif.id);
      setUnreadCount((prev) => Math.max(0, prev - 1));
      setNotifications((prev) =>
        prev.map((n) => (n.id === notif.id ? { ...n, read_at: new Date().toISOString() } : n))
      );
    }
    if (notif.payload_json?.report_id || notif.kind.includes("report")) {
      navigate("/reports");
      setShowNotifications(false);
    }
  };

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

        {/* Notifications Popover */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setShowNotifications((prev) => !prev)}
            aria-label="Open notifications"
            className={cn(
              "relative flex h-10 w-10 items-center justify-center rounded-full border border-border/70 bg-card/70 shadow-[0_10px_25px_rgba(15,23,42,0.06)] transition-all duration-200 hover:border-cyan-400 hover:text-cyan-400 focus:outline-none",
              showNotifications && "border-cyan-400 text-cyan-400 ring-2 ring-cyan-400/20 shadow-[0_0_20px_rgba(6,182,212,0.25)]"
            )}
          >
            <Bell className="h-5 w-5" />
            {unreadCount > 0 && (
              <span className="absolute -right-1 -top-1 flex h-[20px] min-w-[20px] items-center justify-center rounded-full bg-rose-500 px-1 text-[11px] font-bold text-white shadow-[0_0_12px_rgba(244,63,94,0.7)] animate-pulse">
                {unreadCount > 9 ? "9+" : unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-[52px] z-50 w-[420px] max-w-[90vw] overflow-hidden rounded-2xl border border-border/80 bg-background/95 shadow-2xl backdrop-blur-2xl ring-1 ring-black/10 dark:border-white/10 dark:bg-[#0b1120]/95 dark:shadow-[0_20px_60px_rgba(0,0,0,0.7)]">
              {/* Header */}
              <div className="flex items-center justify-between border-b border-border/60 bg-muted/40 px-4 py-3 dark:border-white/10 dark:bg-white/[0.03]">
                <div className="flex items-center gap-2">
                  <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
                    <Bell className="h-4 w-4" />
                  </div>
                  <span className="text-[14px] font-bold text-foreground">Notifications</span>
                  {unreadCount > 0 ? (
                    <span className="rounded-full bg-cyan-500/15 px-2 py-0.5 text-[11px] font-semibold text-cyan-400 border border-cyan-500/25">
                      {unreadCount} new
                    </span>
                  ) : (
                    <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] font-semibold text-muted-foreground">
                      All caught up
                    </span>
                  )}
                </div>
                {unreadCount > 0 && (
                  <button
                    type="button"
                    onClick={handleMarkAllRead}
                    className="flex items-center gap-1 text-[12px] font-semibold text-cyan-500 hover:text-cyan-400 transition-colors"
                  >
                    <CheckCheck className="h-3.5 w-3.5" />
                    <span>Mark all read</span>
                  </button>
                )}
              </div>

              {/* Notification List */}
              <div className="max-h-[380px] divide-y divide-border/40 overflow-y-auto dark:divide-white/5">
                {notifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted/60 text-muted-foreground/60 mb-3">
                      <Bell className="h-6 w-6" />
                    </div>
                    <p className="text-[13px] font-medium text-foreground">No notifications yet</p>
                    <p className="text-[12px] text-muted-foreground mt-0.5">
                      Security scan reports sent to your email will appear here.
                    </p>
                  </div>
                ) : (
                  notifications.map((notif) => {
                    const isReport =
                      notif.kind.includes("report") ||
                      notif.title.toLowerCase().includes("report");
                    const isUnread = !notif.read_at;

                    return (
                      <div
                        key={notif.id}
                        onClick={() => handleNotificationClick(notif)}
                        className={cn(
                          "group relative flex cursor-pointer items-start gap-3 p-3.5 transition-all duration-150 hover:bg-muted/60 dark:hover:bg-white/[0.04]",
                          isUnread && "bg-cyan-500/[0.04] dark:bg-cyan-500/[0.06]"
                        )}
                      >
                        {/* Report Delivery Icon */}
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-500/25 bg-cyan-500/10 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.15)] mt-0.5">
                          <Mail className="h-4 w-4" />
                        </div>

                        {/* Text info */}
                        <div className="flex-1 min-w-0 pr-1">
                          <div className="flex items-center justify-between gap-2">
                            <span
                              className={cn(
                                "text-[13px] font-semibold truncate",
                                isUnread ? "text-foreground font-bold" : "text-muted-foreground"
                              )}
                            >
                              {notif.title}
                            </span>
                            <span className="text-[11px] font-medium text-muted-foreground whitespace-nowrap">
                              {formatRelativeTime(notif.created_at)}
                            </span>
                          </div>

                          <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground group-hover:text-foreground/90 transition-colors line-clamp-2">
                            {notif.message}
                          </p>

                          <div className="mt-2 flex items-center gap-2">
                            <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-400">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]" />
                              Sent to Email
                            </span>
                            <span className="text-[11px] font-semibold text-cyan-400 hover:underline flex items-center gap-0.5">
                              View Report <ChevronRight className="h-3 w-3" />
                            </span>
                          </div>
                        </div>

                        {/* Unread indicator dot */}
                        {isUnread && (
                          <div className="flex h-full items-center pt-2">
                            <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>

              {/* Footer */}
              <div className="border-t border-border/60 bg-muted/20 px-4 py-2.5 text-center dark:border-white/10 dark:bg-white/[0.02]">
                <button
                  type="button"
                  onClick={() => {
                    navigate("/reports");
                    setShowNotifications(false);
                  }}
                  className="text-[12px] font-bold text-cyan-500 hover:text-cyan-400 transition-colors flex items-center justify-center gap-1.5 w-full"
                >
                  <FileText className="h-3.5 w-3.5" />
                  <span>Open Reports Archive</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Hacker Pet mount preserved completely untouched */}
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