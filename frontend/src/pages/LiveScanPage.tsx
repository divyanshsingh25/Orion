import { useEffect, useMemo, useState, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, Ban, CheckCircle2, Cpu, Database, FileText, LockKeyhole, Radar, Server, ShieldAlert, Square, Zap } from "lucide-react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ProgressBar } from "@/components/ui/progress";
import { cancelScan, getActiveScan, getDashboardData, getScan, getScanWebSocketUrl } from "@/services/api";
import type { LiveModule, TerminalEvent } from "@/types/dashboard";
import { cn } from "@/utils/cn";
import { useNavigate, useSearchParams } from "react-router-dom";

const levelClass: Record<string, string> = {
  INFO: "text-sky-400",
  SCAN: "text-cyan-300",
  FOUND: "text-amber-300",
  WARN: "text-rose-400",
};

const moduleIcons = [Radar, LockKeyhole, Database, Server, Cpu, ShieldAlert];
const statusTone = { Complete: "success", Scanning: "running", Queued: "neutral", Cancelled: "failed" } as const;

function formatEta(seconds: number): string {
  if (seconds <= 0) return "—";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
}

export function LiveScanPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const urlScanId = searchParams.get("scanId") ?? "";
  const urlTarget = searchParams.get("target") ?? "";

  // Query backend for active running scan (or most recent scan) as source of truth
  const activeScanQuery = useQuery({
    queryKey: ["active-scan"],
    queryFn: getActiveScan,
    staleTime: 2000,
  });

  // Resolve scanId: URL param -> backend active scan -> localStorage fallback
  const scanId = useMemo(() => {
    if (urlScanId) return urlScanId;
    if (activeScanQuery.data?.id) return activeScanQuery.data.id;
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage.getItem("orion.active_scan_id") || "";
    }
    return "";
  }, [urlScanId, activeScanQuery.data?.id]);

  const dashboardQuery = useQuery({ queryKey: ["live-scan-dashboard"], queryFn: getDashboardData });

  const scanQuery = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const data = query.state.data as { status?: string } | undefined;
      return data?.status === "completed" || data?.status === "failed" || data?.status === "cancelled" ? false : 1500;
    },
  });

  // Sync resolved scanId and target to URL so browser refresh and bookmarking preserves it
  useEffect(() => {
    if (scanId) {
      if (typeof window !== "undefined" && window.localStorage) {
        window.localStorage.setItem("orion.active_scan_id", scanId);
      }
      if (!urlScanId) {
        const nextParams = new URLSearchParams(searchParams);
        nextParams.set("scanId", scanId);
        const resolvedTarget = scanQuery.data?.target_url || activeScanQuery.data?.target_url || activeScanQuery.data?.current_url;
        if (resolvedTarget) {
          nextParams.set("target", resolvedTarget);
        }
        setSearchParams(nextParams, { replace: true });
      }
    }
  }, [scanId, urlScanId, searchParams, setSearchParams, scanQuery.data?.target_url, activeScanQuery.data]);

  // Resolve canonical target URL
  const target = useMemo(() => {
    if (urlTarget) return urlTarget;
    if (scanQuery.data?.target_url) return scanQuery.data.target_url;
    if (activeScanQuery.data?.target_url) return activeScanQuery.data.target_url;
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage.getItem("orion.active_target") || "api.orion.sec";
    }
    return "api.orion.sec";
  }, [urlTarget, scanQuery.data?.target_url, activeScanQuery.data?.target_url]);

  const [eventsState, setEventsState] = useState<TerminalEvent[]>([]);
  const [modulesState, setModulesState] = useState<LiveModule[]>([]);
  const [progress, setProgress] = useState(0);
  const [requestsCount, setRequestsCount] = useState(0);
  const [endpointsCount, setEndpointsCount] = useState(0);
  const [findingsCount, setFindingsCount] = useState(0);
  const [etaSeconds, setEtaSeconds] = useState(0);
  const [scanStatus, setScanStatus] = useState<string>("queued");
  const [isCancelling, setIsCancelling] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Clear local component state when switching to a different scan
  useEffect(() => {
    setModulesState([]);
    setEventsState([]);
    setProgress(0);
    setRequestsCount(0);
    setEndpointsCount(0);
    setFindingsCount(0);
    setEtaSeconds(0);
    setScanStatus("queued");
  }, [scanId]);

  // Sync from HTTP polling / persisted backend state
  useEffect(() => {
    if (scanQuery.data) {
      const data = scanQuery.data;

      if (typeof data.progress_percent === "number") {
        setProgress((prev) => Math.max(prev, data.progress_percent || 0));
      }
      if (data.status) {
        setScanStatus(data.status);
      }
      if (typeof data.total_findings === "number") {
        setFindingsCount((prev) => Math.max(prev, data.total_findings || 0));
      }
      if (typeof data.requests_count === "number" && data.requests_count > 0) {
        setRequestsCount(data.requests_count);
      }
      if (typeof data.endpoints_count === "number" && data.endpoints_count > 0) {
        setEndpointsCount(data.endpoints_count);
      }
      if (typeof data.eta_seconds === "number") {
        setEtaSeconds(data.eta_seconds);
      }

      // Pre-populate module cards from backend
      if (data.live_modules && data.live_modules.length > 0) {
        setModulesState(data.live_modules);
      } else if (data.current_module) {
        const modName = data.current_module;
        setModulesState((current) => {
          const next = [...current];
          const idx = next.findIndex((m) => m.name.toLowerCase() === modName.toLowerCase());
          const isDone = data.status === "completed";
          const modEntry: LiveModule = {
            name: modName,
            status: isDone ? "Complete" : "Scanning",
            progress: data.progress_percent ?? 0,
            findings: data.total_findings ?? 0,
          };
          if (idx >= 0) {
            next[idx] = { ...next[idx], ...modEntry };
          } else {
            next.push(modEntry);
          }
          return next;
        });
      }

      // Pre-populate terminal events from backend
      if (data.live_events && data.live_events.length > 0) {
        setEventsState((current) => {
          if (current.length === 0) {
            return data.live_events!;
          }
          const seen = new Set(current.map((e) => `${e.time}|${e.message}`));
          const missing = data.live_events!.filter((e) => !seen.has(`${e.time}|${e.message}`));
          if (missing.length > 0) {
            return [...current, ...missing].slice(0, 150);
          }
          return current;
        });
      }
    }
  }, [scanQuery.data]);

  // WebSocket live connection with auto-reconnect
  useEffect(() => {
    const accessToken = window.localStorage.getItem("orion.access_token");
    if (!scanId || !accessToken) {
      return;
    }

    let isSubscribed = true;
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    function connect() {
      if (!isSubscribed) return;
      try {
        const wsUrl = getScanWebSocketUrl(scanId, accessToken!);
        const socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          // Connected
        };

        socket.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data) as {
              event?: string;
              status?: string;
              progress?: number;
              current_module?: string;
              total_findings?: number;
              requests_count?: number;
              endpoints_count?: number;
              findings_count?: number;
              eta_seconds?: number;
              log?: { time: string; level: string; message: string };
              module_info?: { name: string; status: string; index?: number; total?: number; findings?: number };
            };

            // Update live metrics
            if (typeof payload.progress === "number") {
              setProgress(payload.progress);
            }
            if (typeof payload.requests_count === "number") {
              setRequestsCount(payload.requests_count);
            }
            if (typeof payload.endpoints_count === "number") {
              setEndpointsCount(payload.endpoints_count);
            }
            if (typeof payload.findings_count === "number") {
              setFindingsCount(payload.findings_count);
            }
            if (typeof payload.eta_seconds === "number") {
              setEtaSeconds(payload.eta_seconds);
            }

            // Update module card states
            if (payload.module_info) {
              const info = payload.module_info;
              setModulesState((current) => {
                const next = [...current];
                const existingIdx = next.findIndex((m) => m.name.toLowerCase() === info.name.toLowerCase());
                const moduleEntry: LiveModule = {
                  name: info.name,
                  status: info.status === "Complete" ? "Complete" : info.status === "Scanning" ? "Scanning" : "Queued",
                  progress: payload.progress ?? 0,
                  findings: info.findings ?? (payload.findings_count ?? 0),
                };
                if (existingIdx >= 0) {
                  next[existingIdx] = moduleEntry;
                } else {
                  // Mark previous scanning module as complete if a new one starts
                  for (let i = 0; i < next.length; i++) {
                    if (next[i].status === "Scanning") {
                      next[i] = { ...next[i], status: "Complete" };
                    }
                  }
                  next.push(moduleEntry);
                }
                return next;
              });
            } else if (payload.current_module) {
              const modName = payload.current_module;
              setModulesState((current) => {
                const next = [...current];
                const existingIdx = next.findIndex((m) => m.name.toLowerCase() === modName.toLowerCase());
                const moduleEntry: LiveModule = {
                  name: modName,
                  status: payload.event === "module_complete" ? "Complete" : "Scanning",
                  progress: payload.progress ?? 0,
                  findings: payload.findings_count ?? 0,
                };
                if (existingIdx >= 0) {
                  next[existingIdx] = moduleEntry;
                } else {
                  for (let i = 0; i < next.length; i++) {
                    if (next[i].status === "Scanning") {
                      next[i] = { ...next[i], status: "Complete" };
                    }
                  }
                  next.push(moduleEntry);
                }
                return next;
              });
            }

            // Append live terminal log events
            if (payload.log) {
              const logEntry: TerminalEvent = {
                time: payload.log.time,
                level: (payload.log.level as TerminalEvent["level"]) || "INFO",
                message: payload.log.message,
              };
              setEventsState((current) => [logEntry, ...current].slice(0, 100));
            }

            if (payload.event === "scan_completed") {
              setScanStatus("completed");
              setProgress(100);
              queryClient.invalidateQueries({ queryKey: ["active-scan"] });
            }
            if (payload.event === "scan_failed") {
              setScanStatus("failed");
              queryClient.invalidateQueries({ queryKey: ["active-scan"] });
            }
            if (payload.event === "scan_cancelled" || payload.status === "cancelled") {
              setScanStatus("cancelled");
              queryClient.invalidateQueries({ queryKey: ["active-scan"] });
            }
          } catch {
            // Ignore parse errors
          }
        };

        socket.onclose = () => {
          if (isSubscribed && scanStatus !== "completed" && scanStatus !== "failed" && scanStatus !== "cancelled") {
            reconnectTimeout = setTimeout(connect, 2000);
          }
        };

        socket.onerror = () => {
          socket.close();
        };
      } catch {
        if (isSubscribed) {
          reconnectTimeout = setTimeout(connect, 3000);
        }
      }
    }

    connect();

    return () => {
      isSubscribed = false;
      clearTimeout(reconnectTimeout);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [scanId, scanStatus]);

  const handleCancelScan = async () => {
    if (!scanId || isCancelling) return;
    setIsCancelling(true);
    try {
      await cancelScan(scanId);
      setScanStatus("cancelled");
      queryClient.invalidateQueries({ queryKey: ["active-scan"] });
      const timestamp = new Date().toLocaleTimeString("en-GB", { hour12: false });
      setEventsState((current) => [
        {
          time: timestamp,
          level: "WARN",
          message: "Scan cancelled by user. Stopped all active network probes and processes on target.",
        },
        ...current,
      ]);
    } catch (error) {
      console.error("Failed to cancel scan:", error);
    } finally {
      setIsCancelling(false);
      setShowConfirmModal(false);
    }
  };

  const effProgress = scanQuery.data?.progress_percent !== undefined
    ? Math.max(progress, scanQuery.data.progress_percent)
    : progress;

  const effStatus = scanQuery.data?.status || scanStatus;

  const events = useMemo(() => {
    if (eventsState.length > 0) return eventsState;
    if (scanQuery.data?.live_events && scanQuery.data.live_events.length > 0) return scanQuery.data.live_events;
    return (dashboardQuery.data?.terminalEvents ?? []) as TerminalEvent[];
  }, [eventsState, scanQuery.data?.live_events, dashboardQuery.data?.terminalEvents]);

  const modules = useMemo(() => {
    const backendMods = scanQuery.data?.live_modules || [];
    if (backendMods.length > 0 && backendMods.length >= modulesState.length) {
      const stateMap = new Map(modulesState.map((m) => [m.name.toLowerCase(), m]));
      return backendMods.map((bMod) => {
        const live = stateMap.get(bMod.name.toLowerCase());
        return live ? { ...bMod, ...live } : bMod;
      });
    }
    if (modulesState.length > 0) return modulesState;
    return (dashboardQuery.data?.liveModules ?? []) as LiveModule[];
  }, [modulesState, scanQuery.data?.live_modules, dashboardQuery.data?.liveModules]);

  const effRequests = requestsCount > 0 ? requestsCount : (scanQuery.data?.requests_count || 0);
  const effEndpoints = endpointsCount > 0 ? endpointsCount : (scanQuery.data?.endpoints_count || 0);
  const effFindings = findingsCount > 0 ? findingsCount : (scanQuery.data?.total_findings || 0);

  const securityScore = effFindings > 0 ? Math.max(0, Math.round(100 - effFindings * 3)) : 100;
  const isScanning = effStatus === "running" || effStatus === "queued";

  const visibleModules = useMemo(() => {
    // If the scan is fully completed, show all modules
    if (effStatus === "completed") {
      return modules.map((m) => ({ ...m, status: "Complete" as const, progress: 100 }));
    }

    // Find the latest module currently in progress
    let scanningIndex = -1;
    for (let i = modules.length - 1; i >= 0; i--) {
      if (modules[i].status === "Scanning") {
        scanningIndex = i;
        break;
      }
    }

    if (scanningIndex >= 0) {
      // Strictly show only modules up to and including the actively scanning module.
      // Every prior module is guaranteed Complete, active module is Scanning,
      // and ALL downstream queued modules remain hidden until reached!
      return modules.slice(0, scanningIndex + 1).map((m, idx) => {
        if (idx < scanningIndex) {
          return { ...m, status: "Complete" as const, progress: 100 };
        }
        return m;
      });
    }

    // If between modules or queued, only show finished modules
    const completed = modules.filter((m) => m.status === "Complete" || m.status === "Cancelled");
    if (completed.length === 0 && modules.length > 0 && isScanning) {
      return [{ ...modules[0], status: "Scanning" as const, progress: effProgress || 1 }];
    }
    return completed;
  }, [modules, effStatus, isScanning, effProgress]);
  const statusLabel =
    effStatus === "completed"
      ? "Complete"
      : effStatus === "failed"
      ? "Failed"
      : effStatus === "cancelled"
      ? "Cancelled"
      : `Scanning ${effProgress}%`;

  const detectionSummary = [
    { label: "Requests", value: effRequests > 1000 ? `${(effRequests / 1000).toFixed(1)}k` : String(effRequests), icon: Zap },
    { label: "Endpoints", value: String(effEndpoints), icon: Server },
    { label: "Findings", value: String(effFindings), icon: ShieldAlert },
    { label: "Secure", value: `${securityScore}%`, icon: CheckCircle2 },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-[22px] border border-rose-500/30 bg-[#0B132B]/95 p-6 shadow-2xl shadow-rose-950/60 backdrop-blur-md animate-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-rose-500/15 text-rose-400">
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <h3 className="text-[19px] font-bold text-white">Cancel Target Assessment?</h3>
                <p className="text-[13px] text-muted-foreground">Target: {target}</p>
              </div>
            </div>
            <p className="mt-4 text-[14px] leading-relaxed text-slate-300">
              Are you sure you want to stop the ongoing scan? This will immediately terminate all active network requests, port scans, and vulnerability probes running against <span className="font-mono font-semibold text-cyan-400">{target}</span>.
            </p>
            <div className="mt-6 flex items-center justify-end gap-3">
              <Button
                variant="outline"
                className="h-10 px-4 font-semibold"
                onClick={() => setShowConfirmModal(false)}
                disabled={isCancelling}
              >
                Keep Scanning
              </Button>
              <Button
                variant="destructive"
                className="h-10 px-4 font-bold border-rose-500/40 bg-rose-600 text-white hover:bg-rose-700 shadow-[0_10px_25px_rgba(225,29,72,0.3)]"
                onClick={handleCancelScan}
                disabled={isCancelling}
              >
                {isCancelling ? "Cancelling..." : "Yes, Cancel Scan"}
              </Button>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="section-label mb-3">Runtime Assessment</div>
          <h1 className="text-[38px] font-bold leading-none tracking-[-0.03em]">Live Scan</h1>
          <p className="muted-copy mt-4">Real-time telemetry, module execution, and detection feed for {target}.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {isScanning && (
            <Button
              variant="destructive"
              className="mt-2 h-11 px-4 border border-rose-500/40 bg-rose-500/15 text-rose-400 hover:bg-rose-500/25 hover:text-rose-300 transition-all font-bold shadow-[0_10px_20px_rgba(244,63,94,0.15)]"
              onClick={() => setShowConfirmModal(true)}
              disabled={isCancelling}
            >
              <Square className="h-4 w-4 fill-rose-500 text-rose-500" />
              {isCancelling ? "Cancelling..." : "Cancel Scan"}
            </Button>
          )}
          <Button
            className={cn(
              "mt-2 h-11 px-4",
              effStatus === "cancelled" && "border-rose-500/30 bg-rose-500/15 text-rose-400 pointer-events-none",
              effStatus === "completed" && "border-emerald-500/30 bg-emerald-500/15 text-emerald-400 pointer-events-none",
              effStatus === "failed" && "border-rose-500/30 bg-rose-500/15 text-rose-400 pointer-events-none"
            )}
          >
            {effStatus === "completed" ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            ) : effStatus === "cancelled" ? (
              <Ban className="h-4 w-4 text-rose-400" />
            ) : effStatus === "failed" ? (
              <AlertTriangle className="h-4 w-4 text-rose-400" />
            ) : (
              <Activity className="h-4 w-4 animate-pulse text-cyan-400" />
            )}
            {statusLabel}
          </Button>
          {effStatus === "completed" && (
            <Button
              variant="outline"
              className="mt-2 h-11 px-4 border border-emerald-500/40 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 transition-all font-bold shadow-[0_10px_20px_rgba(16,185,129,0.15)]"
              onClick={() => navigate("/reports")}
            >
              <FileText className="h-4 w-4 mr-2" />
              View Report
            </Button>
          )}
        </div>
      </div>

      <div className="mt-7 grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
        <section className="panel overflow-hidden p-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-[22px] font-bold">Scan Progress</h2>
              <p className="mt-2 text-[15px] font-semibold text-muted-foreground">{events.length} event checks across {modules.length} active modules</p>
            </div>
            <div className={cn(
              "rounded-full border px-3 py-1.5 text-[13px] font-bold",
              effStatus === "cancelled"
                ? "border-rose-300/30 bg-rose-400/10 text-rose-400"
                : effStatus === "completed"
                ? "border-emerald-300/30 bg-emerald-400/10 text-emerald-400"
                : "border-cyan-300/30 bg-cyan-400/10 text-cyan-500"
            )}>
              {effStatus === "completed" ? "Done" : effStatus === "cancelled" ? "Cancelled" : `ETA ${formatEta(etaSeconds)}`}
            </div>
          </div>
          <div className="mt-6">
            <ProgressBar value={effProgress} className="h-3" />
            <div className="mt-3 flex justify-between text-[12px] font-bold text-muted-foreground"><span>Discovery</span><span>Authorization</span><span>Runtime</span><span>Report</span></div>
          </div>

          <div className="mt-7 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {visibleModules.map((module, index) => {
              const originalIndex = modules.findIndex((m) => m.name.toLowerCase() === module.name.toLowerCase());
              const Icon = moduleIcons[(originalIndex >= 0 ? originalIndex : index) % moduleIcons.length] ?? ShieldAlert;
              return (
                <motion.div
                  key={module.name}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25 }}
                  className="rounded-[18px] border border-border/70 bg-card/70 p-4 transition-all duration-300 hover:border-cyan-400/40"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex h-10 w-10 items-center justify-center rounded-[12px] bg-cyan-400/[0.12] text-cyan-500"><Icon className="h-5 w-5" /></div>
                    <Badge tone={statusTone[module.status]}>{module.status}</Badge>
                  </div>
                  <h3 className="mt-4 text-[16px] font-bold">{module.name}</h3>
                  <div className="mt-2 flex items-center justify-between text-[13px] font-bold text-muted-foreground">
                    <span>{module.status === "Complete" ? "100% complete" : `${module.progress}% complete`}</span>
                    <span>{module.findings} findings</span>
                  </div>
                  <ProgressBar value={module.status === "Complete" ? 100 : module.progress} className="mt-3 h-2" />
                </motion.div>
              );
            })}
          </div>
        </section>

        <section className="space-y-5">
          <div className="panel p-6">
            <h2 className="text-[22px] font-bold">Detection Summary</h2>
            <div className="mt-5 grid grid-cols-2 gap-3.5">
              {detectionSummary.map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.label} className="rounded-[18px] border border-border/70 bg-card/70 p-4">
                    <Icon className="h-5 w-5 text-cyan-500" />
                    <div className="mt-4 font-mono text-[28px] font-bold leading-none">{item.value}</div>
                    <div className="mt-2 text-[12px] font-bold uppercase tracking-[0.08em] text-muted-foreground">{item.label}</div>
                  </div>
                );
              })}
            </div>

            {scanStatus === "cancelled" ? (
              <div className="mt-6 rounded-[18px] border border-rose-300/30 bg-rose-400/10 p-4 text-[14px] text-rose-500 dark:border-rose-400/20 dark:bg-rose-400/[0.08]">
                <div className="font-bold flex items-center gap-2">
                  <Ban className="h-4 w-4 text-rose-400" />
                  Scan Cancelled
                </div>
                <p className="mt-1 text-muted-foreground">
                  Assessment execution was cancelled by user. All active requests, crawler processes, and probes targeting {target} have been terminated.
                </p>
              </div>
            ) : (
              <div className="mt-6 rounded-[18px] border border-amber-300/30 bg-amber-400/10 p-4 text-[14px] text-amber-500 dark:border-amber-400/20 dark:bg-amber-400/[0.08]">
                <div className="font-bold flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
                  </span>
                  {scanStatus === "completed" ? "Assessment Finished" : "Active phase"}
                </div>
                <p className="mt-1 text-muted-foreground">
                  {scanStatus === "completed"
                    ? "All assessment modules completed successfully. Telemetry and findings have been compiled."
                    : `${modules.find((m) => m.status === "Scanning")?.name ?? "Assessment engine"} is actively probing the target. Findings and telemetries are streamed in real time.`}
                </p>
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="panel mt-6 p-6">
        <div className="flex items-center justify-between">
          <div><h2 className="text-[22px] font-bold">Live Logs</h2><p className="mt-1 text-[15px] font-medium text-muted-foreground">{target}</p></div>
          <div className="text-[13px] font-mono text-muted-foreground">{events.length} events</div>
        </div>
        <div className="mt-5 rounded-[18px] border border-slate-800 bg-[#070d18] p-4 font-mono text-[13px] text-slate-200">
          <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-2">
            {events.map((event, index) => (
              <div key={`${event.time}-${index}`} className="flex items-start gap-3">
                <span className="text-slate-500">{event.time}</span>
                <span className={cn("font-bold min-w-[70px]", levelClass[event.level] ?? "text-cyan-300")}>[{event.level}]</span>
                <span className="break-all">{event.message}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </motion.div>
  );
}