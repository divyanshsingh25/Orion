import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  ArrowUpDown,
  Search,
  RadioTower,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Play,
  XCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import { getDashboardData } from "@/services/api";
import type { ScanHistoryRow } from "@/types/dashboard";

type SortField = "started" | "target" | "duration" | "critical" | "status";
type SortOrder = "asc" | "desc";

export function ScanHistoryPage() {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({
    queryKey: ["scan-history"],
    queryFn: getDashboardData,
  });

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [sortField, setSortField] = useState<SortField>("started");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  const rawRows = (data?.scanHistory ?? []) as ScanHistoryRow[];

  // Quick stats calculations
  const stats = useMemo(() => {
    const total = rawRows.length;
    const completed = rawRows.filter((r) => r.status?.toLowerCase() === "completed").length;
    const totalVulns = rawRows.reduce(
      (sum, r) => sum + (r.critical || 0) + (r.high || 0) + (r.medium || 0) + (r.low || 0),
      0
    );
    const criticalVulns = rawRows.reduce((sum, r) => sum + (r.critical || 0), 0);
    return { total, completed, totalVulns, criticalVulns };
  }, [rawRows]);

  // Unique scan types for filter dropdown
  const scanTypes = useMemo(() => {
    const types = new Set<string>();
    rawRows.forEach((r) => {
      if (r.type) types.add(r.type);
    });
    return Array.from(types);
  }, [rawRows]);

  // Filter & sort rows
  const filteredRows = useMemo(() => {
    return rawRows
      .filter((row) => {
        // Search
        if (
          searchTerm &&
          !row.target?.toLowerCase().includes(searchTerm.toLowerCase())
        ) {
          return false;
        }
        // Status filter
        if (statusFilter !== "ALL") {
          if (statusFilter === "COMPLETED" && row.status?.toLowerCase() !== "completed") return false;
          if (statusFilter === "RUNNING" && row.status?.toLowerCase() !== "running") return false;
          if (
            statusFilter === "CANCELLED_FAILED" &&
            !["cancelled", "failed"].includes(row.status?.toLowerCase() || "")
          )
            return false;
        }
        // Type filter
        if (typeFilter !== "ALL" && row.type !== typeFilter) {
          return false;
        }
        return true;
      })
      .sort((a, b) => {
        let valA: any = a[sortField];
        let valB: any = b[sortField];

        if (sortField === "critical") {
          valA = (a.critical || 0) * 100 + (a.high || 0) * 10 + (a.medium || 0);
          valB = (b.critical || 0) * 100 + (b.high || 0) * 10 + (b.medium || 0);
        }

        if (valA < valB) return sortOrder === "asc" ? -1 : 1;
        if (valA > valB) return sortOrder === "asc" ? 1 : -1;
        return 0;
      });
  }, [rawRows, searchTerm, statusFilter, typeFilter, sortField, sortOrder]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / itemsPerPage));
  const paginatedRows = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredRows.slice(start, start + itemsPerPage);
  }, [filteredRows, currentPage]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  const getStatusBadge = (status: string) => {
    const s = (status || "").toLowerCase();
    if (s === "completed") {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-0.5 text-[12px] font-semibold text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          COMPLETED
        </span>
      );
    }
    if (s === "running") {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-0.5 text-[12px] font-semibold text-cyan-400 animate-pulse">
          <RadioTower className="h-3.5 w-3.5" />
          RUNNING
        </span>
      );
    }
    if (s === "failed") {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/20 bg-rose-500/10 px-2.5 py-0.5 text-[12px] font-semibold text-rose-400">
          <AlertTriangle className="h-3.5 w-3.5" />
          FAILED
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-500/20 bg-slate-500/10 px-2.5 py-0.5 text-[12px] font-semibold text-slate-400">
        <XCircle className="h-3.5 w-3.5" />
        CANCELLED
      </span>
    );
  };

  return (
    <div className="space-y-7 pb-10">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[32px] font-extrabold tracking-tight text-foreground flex items-center gap-3">
            <RadioTower className="h-8 w-8 text-cyan-400" />
            Scan History
          </h1>
          <p className="mt-1 text-[15px] text-muted-foreground">
            Audit, track, and inspect all historical vulnerability assessments and security runs
          </p>
        </div>
        <button
          onClick={() => navigate("/new-scan")}
          className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2.5 text-[14px] font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all hover:brightness-110 active:scale-[0.98]"
        >
          <Play className="h-4 w-4 fill-white" />
          Launch New Scan
        </button>
      </div>

      {/* Metrics Summary Strip */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border/60 bg-card/60 p-4 shadow-sm backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-muted-foreground">Total Scans Executed</span>
            <RadioTower className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-[26px] font-extrabold tracking-tight text-foreground">
            {stats.total}
          </div>
        </div>

        <div className="rounded-xl border border-border/60 bg-card/60 p-4 shadow-sm backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-muted-foreground">Completed Scans</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-[26px] font-extrabold tracking-tight text-emerald-400">
            {stats.completed}
          </div>
        </div>

        <div className="rounded-xl border border-border/60 bg-card/60 p-4 shadow-sm backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-muted-foreground">Vulnerabilities Found</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-2 text-[26px] font-extrabold tracking-tight text-foreground">
            {stats.totalVulns}
          </div>
        </div>

        <div className="rounded-xl border border-border/60 bg-card/60 p-4 shadow-sm backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-muted-foreground">Critical Vulnerabilities</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="mt-2 text-[26px] font-extrabold tracking-tight text-rose-400">
            {stats.criticalVulns}
          </div>
        </div>
      </div>

      {/* Main Table Panel */}
      <section className="rounded-xl border border-border/80 bg-card/90 p-5 shadow-sm">
        {/* Controls Toolbar */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          {/* Search bar */}
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by target domain (e.g. example.com)..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-lg border border-border/80 bg-background/70 pl-9 pr-4 py-2 text-[14px] text-foreground placeholder:text-muted-foreground focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Status pills */}
            <div className="inline-flex rounded-lg border border-border/70 bg-background/50 p-1 text-[12px] font-medium">
              {[
                { id: "ALL", label: "All" },
                { id: "COMPLETED", label: "Completed" },
                { id: "RUNNING", label: "Running" },
                { id: "CANCELLED_FAILED", label: "Cancelled / Failed" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => {
                    setStatusFilter(tab.id);
                    setCurrentPage(1);
                  }}
                  className={`rounded-md px-3 py-1 transition-all ${
                    statusFilter === tab.id
                      ? "bg-cyan-500 text-white shadow-sm font-semibold"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Type selector */}
            {scanTypes.length > 0 && (
              <div className="flex items-center gap-1.5 rounded-lg border border-border/70 bg-background/50 px-2.5 py-1 text-[12px]">
                <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground" />
                <select
                  value={typeFilter}
                  onChange={(e) => {
                    setTypeFilter(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="bg-transparent text-foreground focus:outline-none cursor-pointer"
                >
                  <option value="ALL">All Scan Types</option>
                  {scanTypes.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Scans Table Container */}
        <div className="mt-5 overflow-x-auto rounded-lg border border-border/70">
          <table className="w-full border-collapse text-left text-[14px]">
            <thead>
              <tr className="border-b border-border/80 bg-muted/30 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
                <th
                  onClick={() => handleSort("target")}
                  className="cursor-pointer px-4 py-3.5 font-semibold transition-colors hover:text-foreground"
                >
                  <div className="flex items-center gap-1.5">
                    Target Host
                    <ArrowUpDown className="h-3.5 w-3.5" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort("status")}
                  className="cursor-pointer px-4 py-3.5 font-semibold transition-colors hover:text-foreground"
                >
                  <div className="flex items-center gap-1.5">
                    Status
                    <ArrowUpDown className="h-3.5 w-3.5" />
                  </div>
                </th>
                <th className="px-4 py-3.5 font-semibold">Scan Type</th>
                <th className="px-4 py-3.5 text-center font-semibold">
                  <div className="inline-flex items-center gap-3">
                    <span className="text-rose-400">Crit</span>
                    <span className="text-orange-400">High</span>
                    <span className="text-amber-400">Med</span>
                    <span className="text-blue-400">Low</span>
                  </div>
                </th>
                <th
                  onClick={() => handleSort("started")}
                  className="cursor-pointer px-4 py-3.5 font-semibold transition-colors hover:text-foreground whitespace-nowrap"
                >
                  <div className="flex items-center gap-1.5">
                    Started
                    <ArrowUpDown className="h-3.5 w-3.5" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort("duration")}
                  className="cursor-pointer px-4 py-3.5 font-semibold transition-colors hover:text-foreground whitespace-nowrap"
                >
                  <div className="flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5" />
                    Duration
                    <ArrowUpDown className="h-3.5 w-3.5" />
                  </div>
                </th>
                <th className="px-4 py-3.5 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    <div className="inline-flex items-center gap-2">
                      <RadioTower className="h-5 w-5 animate-spin text-cyan-400" />
                      Loading historical scan data...
                    </div>
                  </td>
                </tr>
              ) : paginatedRows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    No scans found matching your criteria.
                  </td>
                </tr>
              ) : (
                paginatedRows.map((row, index) => (
                  <tr
                    key={`${row.id || row.target}-${index}`}
                    className="group transition-colors hover:bg-muted/20"
                  >
                    {/* Target Host */}
                    <td className="px-4 py-3.5 font-mono text-[13px] font-semibold text-foreground max-w-[240px] truncate">
                      <span title={row.target} className="hover:text-cyan-400 transition-colors">
                        {row.target}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      {getStatusBadge(row.status)}
                    </td>

                    {/* Scan Type */}
                    <td className="px-4 py-3.5 text-muted-foreground whitespace-nowrap text-[13px]">
                      <span className="rounded bg-muted/60 px-2 py-0.5 text-[12px] font-medium text-foreground">
                        {row.type}
                      </span>
                    </td>

                    {/* Findings Breakdown */}
                    <td className="px-4 py-3.5 text-center">
                      <div className="inline-flex items-center gap-2 text-[12px] font-mono font-semibold">
                        <span
                          className={`rounded px-1.5 py-0.5 ${
                            row.critical > 0
                              ? "bg-rose-500/20 text-rose-400 font-bold"
                              : "text-muted-foreground/50"
                          }`}
                        >
                          {row.critical}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 ${
                            row.high > 0
                              ? "bg-orange-500/20 text-orange-400 font-bold"
                              : "text-muted-foreground/50"
                          }`}
                        >
                          {row.high}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 ${
                            row.medium > 0
                              ? "bg-amber-500/20 text-amber-400 font-bold"
                              : "text-muted-foreground/50"
                          }`}
                        >
                          {row.medium}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 ${
                            row.low > 0
                              ? "bg-blue-500/20 text-blue-400 font-bold"
                              : "text-muted-foreground/50"
                          }`}
                        >
                          {row.low}
                        </span>
                      </div>
                    </td>

                    {/* Started Date */}
                    <td className="px-4 py-3.5 text-[13px] text-muted-foreground whitespace-nowrap">
                      {row.started || "-"}
                    </td>

                    {/* Duration (Formatted clearly with ample width and clock badge) */}
                    <td className="px-4 py-3.5 text-[13px] font-mono font-medium text-foreground whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 rounded-md bg-muted/40 px-2.5 py-1 text-cyan-300">
                        <Clock className="h-3.5 w-3.5 text-cyan-400" />
                        {row.duration || "-"}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => {
                          if (row.id) {
                            navigate(`/live-scan?scanId=${row.id}`);
                          } else {
                            navigate("/live-scan");
                          }
                        }}
                        className="inline-flex items-center gap-1 rounded-md border border-border/80 bg-background/80 px-2.5 py-1 text-[12px] font-medium text-foreground transition-all hover:border-cyan-500 hover:text-cyan-400"
                      >
                        Inspect
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Footer & Pagination */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[13px] text-muted-foreground">
          <div>
            Showing{" "}
            <span className="font-semibold text-foreground">
              {filteredRows.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0}
            </span>{" "}
            to{" "}
            <span className="font-semibold text-foreground">
              {Math.min(currentPage * itemsPerPage, filteredRows.length)}
            </span>{" "}
            of <span className="font-semibold text-foreground">{filteredRows.length}</span> scans
          </div>

          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-background text-foreground transition-colors hover:bg-muted disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <span className="px-2 font-medium text-foreground">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-background text-foreground transition-colors hover:bg-muted disabled:opacity-40"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}