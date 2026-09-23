import React, { useMemo, useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, Filter, Search, ShieldAlert, Sparkles } from "lucide-react";
import { motion } from "framer-motion";
import { useNavigate, useLocation } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ProgressBar } from "@/components/ui/progress";
import { getDashboardData, getFindings } from "@/services/api";
import type { SeverityName, Vulnerability } from "@/types/dashboard";
import { cn } from "@/utils/cn";

const severityTone: Record<string, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};
const filters: Array<"All" | SeverityName> = ["All", "Critical", "High", "Medium", "Low"];

export function VulnerabilitiesPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const initialSeverity = location.state?.severity as SeverityName | undefined;
  const initialDomain = location.state?.domain as string | undefined;
  const initialScanId = location.state?.scanId as string | undefined;

  const [selectedScanId, setSelectedScanId] = useState<string>(initialScanId || "");
  const [active, setActive] = useState<(typeof filters)[number]>(initialSeverity || "All");
  
  const { data: dashboardData } = useQuery({ queryKey: ["dashboard"], queryFn: getDashboardData });
  const scanHistory = useMemo(() => dashboardData?.scanHistory ?? [], [dashboardData]);

  // Synchronize filter when navigating from charts
  useEffect(() => {
    if (initialSeverity && filters.includes(initialSeverity)) {
      setActive(initialSeverity);
    }
  }, [initialSeverity]);

  useEffect(() => {
    if (initialScanId) {
      setSelectedScanId(initialScanId);
    } else if (initialDomain && initialDomain !== "all" && scanHistory.length > 0) {
      const match = scanHistory.find((s: any) => s.target?.toLowerCase().includes(initialDomain.toLowerCase()));
      if (match && match.id) {
        setSelectedScanId(match.id);
      }
    }
  }, [initialScanId, initialDomain, scanHistory]);

  const { data: findingsData, isLoading } = useQuery({ 
    queryKey: ["vulnerabilities", selectedScanId, active], 
    queryFn: () => getFindings(selectedScanId || undefined, active !== "All" ? active : undefined) 
  });
  
  const vulnerabilities = useMemo(() => (findingsData?.items ?? []) as Vulnerability[], [findingsData]);
  const severityCounts = findingsData?.severityCounts;
  const [expanded, setExpanded] = useState("");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => vulnerabilities.filter((item) => {
    const severityMatch = active === "All" || item.severity?.toLowerCase() === active.toLowerCase();
    const queryMatch = `${item.title} ${item.asset} ${item.cwe} ${item.owasp}`.toLowerCase().includes(query.toLowerCase());
    return severityMatch && queryMatch;
  }), [active, query, vulnerabilities]);

  const groupedFindings = useMemo(() => {
    const groups: Record<string, Vulnerability[]> = {};
    filtered.forEach((item) => {
      const baseTitle = item.title;

      if (!groups[baseTitle]) {
        groups[baseTitle] = [];
      }
      groups[baseTitle].push(item);
    });

    const severityWeight: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    };

    return Object.entries(groups)
      .map(([title, items]) => ({
        ...items[0],
        title,
        id: items[0].id,
        count: items.length,
        groupedItems: items,
      }))
      .sort((a, b) => {
        const weightA = severityWeight[String(a.severity).toLowerCase()] ?? 0;
        const weightB = severityWeight[String(b.severity).toLowerCase()] ?? 0;
        if (weightB !== weightA) return weightB - weightA;
        return Number(b.cvss || 0) - Number(a.cvss || 0);
      });
  }, [filtered]);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="section-label mb-3">Findings Management</div>
          <h1 className="text-[38px] font-bold leading-none tracking-[-0.03em]">Vulnerabilities</h1>
          <p className="muted-copy mt-4">Prioritized security issues mapped to OWASP, CWE, CVSS, evidence, and remediation.</p>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {filters.slice(1).map((filter) => {
            const count = severityCounts?.[filter.toLowerCase() as keyof typeof severityCounts] 
              ?? vulnerabilities.filter((item) => item.severity?.toLowerCase() === filter.toLowerCase()).length;
            const isSelected = active === filter;
            return (
              <button
                key={filter}
                type="button"
                onClick={() => setActive(active === filter ? "All" : filter)}
                className={cn(
                  "thin-panel min-w-[94px] px-4 py-3 text-center transition cursor-pointer hover:border-cyan-500/50",
                  isSelected && "border-cyan-500/80 bg-cyan-500/10 shadow-[0_0_15px_rgba(14,165,233,0.15)]"
                )}
              >
                <div className="text-[24px] font-bold">{count}</div>
                <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-muted-foreground">{filter}</div>
              </button>
            );
          })}
        </div>
      </div>

      <section className="panel mt-7 overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-border/70 p-5">
          <div className="relative min-w-[200px] flex-1">
            <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={query} onChange={(event) => setQuery(event.target.value)} className="pl-11" placeholder="Search by asset, CWE, OWASP, title..." />
          </div>
          <div className="flex items-center gap-2">
            <select 
              value={selectedScanId} 
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="h-11 rounded-[13px] border border-border/70 bg-card/70 px-4 text-[14px] font-bold outline-none focus:border-cyan-500"
            >
              <option value="">All Time Findings</option>
              {scanHistory.map((scan: any) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target} ({scan.started} - {scan.status})
                </option>
              ))}
            </select>
          </div>
          <div className="flex rounded-[14px] border border-border/70 bg-background/60 p-1">
            {filters.map((filter) => (
              <button key={filter} type="button" onClick={() => setActive(filter)} className={cn("h-9 rounded-[10px] px-3 text-[13px] font-bold transition", active === filter ? "bg-cyan-500 text-white shadow-[0_10px_24px_rgba(14,165,233,0.28)]" : "text-muted-foreground hover:text-foreground")}>{filter}</button>
            ))}
          </div>
          <button type="button" className="flex h-11 items-center gap-2 rounded-[13px] border border-border/70 bg-card/70 px-4 text-[14px] font-bold"><Filter className="h-4 w-4" /> Filters</button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1080px] border-collapse text-left">
            <thead className="bg-slate-950/[0.025] dark:bg-white/[0.03]">
              <tr className="h-12 text-[12px] font-bold uppercase tracking-[0.12em] text-muted-foreground">
                <th className="px-5">Finding</th>
                <th className="px-5">Asset</th>
                <th className="px-5">OWASP</th>
                <th className="px-5">CWE</th>
                <th className="px-5">CVSS</th>
                <th className="px-5">Severity</th>
                <th className="px-5">Status</th>
                <th className="px-5" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-[14px] font-medium text-muted-foreground">
                    <div className="flex items-center justify-center gap-2">
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
                      Loading vulnerabilities...
                    </div>
                  </td>
                </tr>
              ) : groupedFindings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-[14px] font-medium text-muted-foreground">
                    No vulnerabilities found matching the selected criteria.
                  </td>
                </tr>
              ) : (
                groupedFindings.map((group) => (
                  <React.Fragment key={group.id}>
                    <tr className={cn("border-t border-border/70 align-top transition hover:bg-cyan-400/[0.045]", expanded === group.id && "bg-cyan-400/[0.025]")}>
                      <td className="px-5 py-4">
                        <div className="text-[15px] font-bold">
                          {group.title}
                          {group.count > 1 && (
                            <span className="ml-3 inline-flex items-center justify-center rounded-[8px] bg-cyan-500/15 px-2 py-0.5 text-[12px] font-bold text-cyan-500 dark:bg-cyan-500/20 dark:text-cyan-400">
                              {group.count} endpoints
                            </span>
                          )}
                        </div>
                        <div className="mt-1 font-mono text-[12px] font-bold text-muted-foreground">{group.id}</div>
                      </td>
                      <td className="px-5 py-4 font-mono text-[14px] font-bold">
                        {group.count === 1 ? (
                          <div className="max-w-[200px] truncate" title={group.asset}>{group.asset}</div>
                        ) : (
                          <div className="text-cyan-600 dark:text-cyan-400">Multiple Assets</div>
                        )}
                      </td>
                      <td className="px-5 py-4 text-[14px] font-bold text-muted-foreground">{group.owasp}</td>
                      <td className="px-5 py-4 text-[14px] font-bold text-muted-foreground">{group.cwe}</td>
                      <td className="px-5 py-4"><div className="flex min-w-[100px] items-center gap-3"><span className="font-mono text-[15px] font-bold">{group.cvss}</span><ProgressBar value={group.cvss * 10} tone={group.cvss >= 8 ? "red" : group.cvss >= 7 ? "amber" : "cyan"} className="h-2 flex-1" /></div></td>
                      <td className="px-5 py-4"><Badge tone={severityTone[group.severity] || "low"}>{group.severity}</Badge></td>
                    <td className="px-5 py-4"><Badge tone={group.status === "Open" ? "running" : group.status === "In Review" ? "medium" : "neutral"}>{group.status}</Badge></td>
                    <td className="px-5 py-4 text-right">
                      <button 
                        type="button" 
                        onClick={() => setExpanded(expanded === group.id ? "" : group.id)} 
                        className="rounded-full border border-border/70 p-2 transition hover:border-cyan-300 hover:text-cyan-500"
                      >
                        <ChevronDown className={cn("h-4 w-4 transition", expanded === group.id && "rotate-180")} />
                      </button>
                    </td>
                  </tr>
                  {expanded === group.id && (
                    <tr className="bg-background/[0.25]">
                      <td colSpan={8} className="px-5 py-6">
                        <div className="grid gap-6 lg:grid-cols-2">
                          <div className="flex flex-col rounded-[20px] border border-border/70 bg-card/50 p-6">
                            <div className="mb-4 flex items-center justify-between">
                              <div className="flex items-center gap-2 text-[13px] font-bold uppercase tracking-[0.12em] text-muted-foreground">
                                  <ShieldAlert className="h-4 w-4" /> Affected Assets & Evidence
                              </div>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                className="h-8 gap-2 border-cyan-500/20 text-cyan-500 hover:bg-cyan-500/10 hover:text-cyan-400"
                                onClick={() => navigate("/", { state: { askAiAbout: group } })}
                              >
                                <Sparkles className="h-3.5 w-3.5" /> Ask Orion AI
                              </Button>
                            </div>
                            <div className="custom-scrollbar max-h-[300px] flex-1 overflow-y-auto pr-2 space-y-3">
                              {group.groupedItems.map((item, idx) => (
                                <div key={item.id || idx} className="rounded-[12px] border border-border/50 bg-background/50 p-4">
                                  <div className="mb-2 break-all font-mono text-[13px] font-bold text-cyan-600 dark:text-cyan-400">{item.asset}</div>
                                  <div className="break-words text-[14px] font-medium text-foreground/80">{item.evidence || "No specific evidence provided."}</div>
                                </div>
                              ))}
                            </div>
                          </div>
                          <div className="rounded-[20px] border border-emerald-400/20 bg-emerald-500/[0.05] p-6">
                            <div className="mb-4 text-[13px] font-bold uppercase tracking-[0.12em] text-emerald-600 dark:text-emerald-500">
                                Remediation Plan
                            </div>
                            <p className="text-[15px] font-medium leading-7 text-emerald-900 dark:text-emerald-100">{group.remediation}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )))}
            </tbody>
          </table>
        </div>
      </section>
    </motion.div>
  );
}