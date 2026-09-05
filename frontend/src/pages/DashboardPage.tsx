import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { FileText, ScanLine, Shield, Settings as SettingsIcon, Globe, Check, Search, X, ChevronDown, Layers } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { getDashboardData } from "@/services/api";
import { MetricCard } from "@/cards/MetricCard";
import { SectionCard } from "@/cards/SectionCard";
import { InfoTile } from "@/cards/InfoTile";
import { AiPanel } from "@/cards/AiPanel";
import { SecurityDonutChart } from "@/charts/SecurityDonutChart";
import { SeverityBarChart } from "@/charts/SeverityBarChart";
import { ActivityTrendChart } from "@/charts/ActivityTrendChart";
import { CoverageRadarChart } from "@/charts/CoverageRadarChart";
import { StatusDonutChart } from "@/charts/StatusDonutChart";
import { AttackVectorChart } from "@/charts/AttackVectorChart";
import { CvssChart } from "@/charts/CvssChart";
import type { AssistantMessage, ChartDatum, Metric, Risk, ScanHistoryRow, Vulnerability, SeverityName } from "@/types/dashboard";
import { cn } from "@/utils/cn";

export function DashboardPage() {
  const navigate = useNavigate();
  const { data } = useQuery({ queryKey: ["dashboard"], queryFn: getDashboardData });
  const location = useLocation();

  const [selectedDomain, setSelectedDomain] = useState<string>("all");
  const [isTargetModalOpen, setIsTargetModalOpen] = useState(false);
  const [domainSearch, setDomainSearch] = useState("");

  // Gather all unique domains from all data sources
  const allDomains = useMemo(() => {
    if (!data) return [];
    const set = new Set<string>();
    data.coverage?.forEach((c: { domain?: string }) => c.domain && set.add(c.domain));
    data.attackSurfaceAssets?.forEach((a: { name?: string }) => a.name && set.add(a.name));
    data.scanHistory?.forEach((s: ScanHistoryRow) => {
      if (s.target) {
        const clean = s.target.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        set.add(clean);
      }
    });
    data.vulnerabilities?.forEach((v: Vulnerability) => {
      if (v.asset) {
        try {
          const u = new URL(v.asset.startsWith("http") ? v.asset : `http://${v.asset}`);
          if (u.hostname) set.add(u.hostname);
        } catch {
          const clean = v.asset.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
          if (clean) set.add(clean);
        }
      }
    });
    return Array.from(set).filter(Boolean);
  }, [data]);

  // Dynamically filter all dashboard charts, metrics, and risk scores based on selected domain
  const filteredData = useMemo(() => {
    if (!data) return null;

    const isAll = selectedDomain === "all";

    // 1. Filter Scans matching selected domain
    const allScans = (data.scanHistory ?? []) as ScanHistoryRow[];
    const scanHistory = isAll
      ? allScans
      : allScans.filter((s) =>
          s.target?.toLowerCase().includes(selectedDomain.toLowerCase())
        );
    const domainScanIds = new Set(scanHistory.map((s) => s.id));

    // 2. Filter Vulnerabilities: check scan_id association OR domain name in asset/url
    const allVulns = (data.vulnerabilities ?? []) as Vulnerability[];
    const vulnerabilities = isAll
      ? allVulns
      : allVulns.filter((v: any) =>
          (v.scan_id && domainScanIds.has(v.scan_id)) ||
          v.target_name?.toLowerCase().includes(selectedDomain.toLowerCase()) ||
          v.asset?.toLowerCase().includes(selectedDomain.toLowerCase()) ||
          v.affected_url?.toLowerCase().includes(selectedDomain.toLowerCase())
        );

    // 3. Severity breakdown: pull direct scan database aggregates
    let criticalCount = scanHistory.reduce((sum, s) => sum + (s.critical || 0), 0);
    let highCount = scanHistory.reduce((sum, s) => sum + (s.high || 0), 0);
    let mediumCount = scanHistory.reduce((sum, s) => sum + (s.medium || 0), 0);
    let lowCount = scanHistory.reduce((sum, s) => sum + (s.low || 0), 0);

    // If scan records don't have broken down counts yet, calculate from vulnerabilities
    if (criticalCount === 0 && highCount === 0 && mediumCount === 0 && lowCount === 0 && vulnerabilities.length > 0) {
      criticalCount = vulnerabilities.filter((v) => v.severity === "Critical").length;
      highCount = vulnerabilities.filter((v) => v.severity === "High").length;
      mediumCount = vulnerabilities.filter((v) => v.severity === "Medium").length;
      lowCount = vulnerabilities.filter((v) => v.severity === "Low").length;
    }

    const totalFindings = criticalCount + highCount + mediumCount + lowCount;

    // 4. Calculate Security Score & Risk Level dynamically
    let score = 100;
    if (totalFindings > 0) {
      const penalty = criticalCount * 25 + highCount * 12 + mediumCount * 4 + lowCount * 1;
      score = Math.round(Math.max(5, Math.min(100, 100 - penalty)));
    }

    let riskLevel = "Low";
    let riskColor = "text-emerald-500";

    if (criticalCount >= 3 || score < 30) {
      riskLevel = "Critical";
      riskColor = "text-red-500";
    } else if (criticalCount > 0 || highCount >= 3 || score < 55) {
      riskLevel = "High";
      riskColor = "text-orange-500";
    } else if (highCount > 0 || mediumCount >= 4 || score < 75) {
      riskLevel = "Medium";
      riskColor = "text-amber-500";
    } else {
      riskLevel = "Low";
      riskColor = "text-emerald-500";
    }

    // 5. Top 4 Metric Cards
    const metrics: Metric[] = isAll
      ? (data.metrics as Metric[])
      : [
          { label: "Target Scope", value: 1, delta: "Active", trend: "up", accent: "cyan" },
          { label: "Total Scans", value: scanHistory.length, delta: `${scanHistory.length} Runs`, trend: "up", accent: "orange" },
          { label: "Vulnerabilities", value: totalFindings, delta: `${criticalCount} Crit`, trend: criticalCount > 0 ? "down" : "up", accent: "yellow" },
          { label: "Security Posture", value: score, delta: `${riskLevel} Risk`, trend: "up", accent: "red" },
        ];

    // 6. Severity Bar Chart
    const severity: ChartDatum[] = [
      { name: "Critical", value: criticalCount, color: "#ef4444" },
      { name: "High", value: highCount, color: "#f97316" },
      { name: "Medium", value: mediumCount, color: "#eab308" },
      { name: "Low", value: lowCount, color: "#14b8a6" },
    ];

    // 7. Attack Vectors
    const attackMap: Record<string, number> = {};
    vulnerabilities.forEach((v) => {
      const type = (v.owasp || (v as any).finding_type || "Web App Security")
        .replace(/_/g, " ")
        .replace(/^A\d{2}:\d{4}\s*-\s*/, "");
      attackMap[type] = (attackMap[type] || 0) + 1;
    });
    const attackColors = ["#22c55e", "#f59e0b", "#06b6d4", "#8b5cf6", "#ec4899"];
    const attacks: ChartDatum[] = Object.entries(attackMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([name, value], i) => ({ name, value, color: attackColors[i % attackColors.length] }));

    // 8. CVSS Distribution
    const cvss: Array<{ range: string; value: number; color: string }> = [
      { range: "Critical (9.0-10)", value: vulnerabilities.filter((v) => v.cvss >= 9).length, color: "#ef4444" },
      { range: "High (7.0-8.9)", value: vulnerabilities.filter((v) => v.cvss >= 7 && v.cvss < 9).length, color: "#f97316" },
      { range: "Medium (4.0-6.9)", value: vulnerabilities.filter((v) => v.cvss >= 4 && v.cvss < 7).length, color: "#eab308" },
      { range: "Low (0.0-3.9)", value: vulnerabilities.filter((v) => v.cvss < 4).length, color: "#14b8a6" },
    ];

    // 9. Scan Status Distribution
    const statusMap: Record<string, number> = { Complete: 0, Scanning: 0, Queued: 0, Failed: 0 };
    scanHistory.forEach((s) => {
      const st = s.status === "Running" ? "Scanning" : s.status === "Completed" ? "Complete" : s.status;
      statusMap[st] = (statusMap[st] || 0) + 1;
    });
    const status: ChartDatum[] = [
      { name: "Complete", value: statusMap["Complete"] || 0, color: "#10b981" },
      { name: "Scanning", value: statusMap["Scanning"] || 0, color: "#06b6d4" },
      { name: "Queued", value: statusMap["Queued"] || 0, color: "#3b82f6" },
      { name: "Failed", value: statusMap["Failed"] || 0, color: "#ef4444" },
    ];

    // 10. Activity Trend
    const activityMap = new Map<string, { Critical: number; High: number; Medium: number }>();
    scanHistory.forEach((row) => {
      const day = new Date(row.started).toLocaleDateString("en-US", { weekday: "short" });
      const current = activityMap.get(day) ?? { Critical: 0, High: 0, Medium: 0 };
      current.Critical += row.critical || 0;
      current.High += row.high || 0;
      current.Medium += row.medium || 0;
      activityMap.set(day, current);
    });
    const activity = Array.from(activityMap.entries()).map(([day, counts]) => ({ day, ...counts }));

    // 11. Risks List
    const risks: Risk[] = vulnerabilities
      .filter((v) => v.severity === "Critical" || v.severity === "High")
      .slice(0, 5)
      .map((v) => ({ title: v.title, severity: v.severity as any }));

    const latestScan = scanHistory[0]?.started ?? "No scans yet";
    const scanDuration = scanHistory[0]?.duration ?? "-";
    const targetLabel = isAll ? "All Targets" : selectedDomain;

    return {
      vulnerabilities,
      scanHistory,
      securityScore: score,
      riskLevel,
      riskColor,
      metrics,
      severity,
      attacks: attacks.length > 0 ? attacks : (data.attackVectors as ChartDatum[]),
      cvss,
      status,
      activity: activity.length > 0 ? activity : data.activity,
      risks: risks.length > 0 ? risks : (data.risks as Risk[]),
      targetLabel,
      latestScan,
      scanDuration,
    };
  }, [data, selectedDomain]);

  if (!data || !filteredData) return null;

  const askAiAbout = location.state?.askAiAbout as Vulnerability | undefined;
  const aiDefaultMessage = askAiAbout ? `Tell me more about the vulnerability: ${askAiAbout.title} on ${askAiAbout.asset}` : undefined;

  const handleSeverityClick = (severity: SeverityName) => {
    let scanId: string | undefined;
    if (selectedDomain !== "all") {
      const match = (data?.scanHistory as ScanHistoryRow[])?.find((s) =>
        s.target?.toLowerCase().includes(selectedDomain.toLowerCase())
      );
      scanId = match?.id;
    }
    navigate("/vulnerabilities", {
      state: {
        severity,
        domain: selectedDomain,
        scanId,
      },
    });
  };

  const filteredModalDomains = allDomains.filter((d) =>
    d.toLowerCase().includes(domainSearch.toLowerCase())
  );

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
      {/* Target Domain Selector Modal */}
      <AnimatePresence>
        {isTargetModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              className="w-full max-w-lg rounded-[22px] border border-border/80 bg-card p-6 shadow-2xl backdrop-blur-md"
            >
              <div className="flex items-center justify-between border-b border-border/60 pb-4">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/[0.12] text-cyan-500 border border-cyan-500/20">
                    <Globe className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-[18px] font-bold text-foreground">Select Target Domain</h3>
                    <p className="text-[13px] text-muted-foreground">Filter all dashboard charts and metrics</p>
                  </div>
                </div>
                <button
                  onClick={() => setIsTargetModalOpen(false)}
                  className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Search Bar */}
              <div className="mt-4 relative">
                <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search targets..."
                  value={domainSearch}
                  onChange={(e) => setDomainSearch(e.target.value)}
                  className="w-full rounded-[12px] border border-border/80 bg-background/80 py-2.5 pl-10 pr-4 text-[14px] font-medium text-foreground outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                />
              </div>

              {/* Domain Options List */}
              <div className="mt-4 max-h-[300px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                {/* Option: All Targets */}
                <div
                  onClick={() => {
                    setSelectedDomain("all");
                    setIsTargetModalOpen(false);
                  }}
                  className={cn(
                    "flex items-center justify-between rounded-[14px] border p-3.5 cursor-pointer transition-all",
                    selectedDomain === "all"
                      ? "border-cyan-500/60 bg-cyan-500/[0.08] text-cyan-400 shadow-sm ring-1 ring-cyan-500/30"
                      : "border-border/60 bg-background/50 hover:border-cyan-400/40 hover:bg-muted/50 text-foreground"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-500">
                      <Layers className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-bold text-[14px]">All Targets (Global Overview)</div>
                      <div className="text-[12px] text-muted-foreground">{allDomains.length} total domains enrolled</div>
                    </div>
                  </div>
                  {selectedDomain === "all" && <Check className="h-4 w-4 text-cyan-500" />}
                </div>

                {/* Individual Domains */}
                {filteredModalDomains.map((domain) => {
                  const isSelected = selectedDomain === domain;
                  const cov = data.coverage?.find((c: { domain?: string }) => c.domain === domain);
                  const scanCount = (data.scanHistory as ScanHistoryRow[]).filter((s) => s.target?.includes(domain)).length;

                  return (
                    <div
                      key={domain}
                      onClick={() => {
                        setSelectedDomain(domain);
                        setIsTargetModalOpen(false);
                      }}
                      className={cn(
                        "flex items-center justify-between rounded-[14px] border p-3.5 cursor-pointer transition-all",
                        isSelected
                          ? "border-cyan-500/60 bg-cyan-500/[0.08] text-cyan-400 shadow-sm ring-1 ring-cyan-500/30"
                          : "border-border/60 bg-background/50 hover:border-cyan-400/40 hover:bg-muted/50 text-foreground"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                          <Globe className="h-4 w-4 text-cyan-500" />
                        </div>
                        <div>
                          <div className="font-bold font-mono text-[14px]">{domain}</div>
                          <div className="text-[12px] text-muted-foreground">{scanCount} scans recorded</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {cov?.score !== undefined && (
                          <span className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-[12px] font-bold text-cyan-500">
                            {cov.score}%
                          </span>
                        )}
                        {isSelected && <Check className="h-4 w-4 text-cyan-500" />}
                      </div>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Header & Action Toolbar */}
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="section-label mb-2">Threat Posture</div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-[32px] font-bold leading-none tracking-[-0.02em]">Security Score</h1>
            {selectedDomain !== "all" && (
              <Badge tone="running" className="gap-1.5 px-3 py-1 text-[13px] font-mono">
                <Globe className="h-3.5 w-3.5 text-cyan-400" />
                {selectedDomain}
              </Badge>
            )}
          </div>
          <p className="muted-copy mt-3">
            {selectedDomain === "all"
              ? "Continuous monitoring and mitigation across all exposed application assets."
              : `Aggregated vulnerability posture and execution telemetry for ${selectedDomain}.`}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Quick Target Domain Switcher Button */}
          <Button
            variant="outline"
            className="h-10 px-3.5 gap-2 border-cyan-500/30 bg-cyan-500/[0.06] text-cyan-400 hover:border-cyan-400 hover:bg-cyan-500/15 font-semibold"
            onClick={() => setIsTargetModalOpen(true)}
          >
            <Globe className="h-4 w-4 text-cyan-400" />
            <span className="font-mono text-[13px]">{selectedDomain === "all" ? "All Targets (Filter)" : selectedDomain}</span>
            <ChevronDown className="h-3.5 w-3.5 opacity-70" />
          </Button>

          <Button className="h-10 px-4" onClick={() => navigate("/new-scan")}>
            <ScanLine className="h-5 w-5" />
            Quick Scan
          </Button>
          <Button variant="outline" className="h-10 px-4" onClick={() => navigate("/reports")}>
            <FileText className="h-5 w-5" />
            View Report
          </Button>
        </div>
      </div>

      {/* Quick Domain Filter Pills Bar */}
      {allDomains.length > 0 && (
        <div className="mb-6 flex items-center gap-2 overflow-x-auto pb-1 custom-scrollbar">
          <span className="text-[12px] font-bold uppercase tracking-wider text-muted-foreground mr-1 shrink-0">
            Target Scope:
          </span>
          <button
            onClick={() => setSelectedDomain("all")}
            className={cn(
              "rounded-full px-3.5 py-1.5 text-[12px] font-bold transition-all shrink-0 border",
              selectedDomain === "all"
                ? "border-cyan-500/60 bg-cyan-500/20 text-cyan-400 shadow-sm ring-1 ring-cyan-500/30"
                : "border-border/60 bg-card/60 text-muted-foreground hover:border-cyan-400/40 hover:text-foreground"
            )}
          >
            All Targets ({allDomains.length})
          </button>
          {allDomains.slice(0, 5).map((dom) => (
            <button
              key={dom}
              onClick={() => setSelectedDomain(dom)}
              className={cn(
                "rounded-full px-3.5 py-1.5 font-mono text-[12px] font-bold transition-all shrink-0 border",
                selectedDomain === dom
                  ? "border-cyan-500/60 bg-cyan-500/20 text-cyan-400 shadow-sm ring-1 ring-cyan-500/30"
                  : "border-border/60 bg-card/60 text-muted-foreground hover:border-cyan-400/40 hover:text-foreground"
              )}
            >
              {dom}
            </button>
          ))}
          {allDomains.length > 5 && (
            <button
              onClick={() => setIsTargetModalOpen(true)}
              className="rounded-full border border-dashed border-cyan-500/40 bg-cyan-500/[0.04] px-3 py-1.5 text-[12px] font-bold text-cyan-400 hover:bg-cyan-500/10 shrink-0"
            >
              +{allDomains.length - 5} more...
            </button>
          )}
        </div>
      )}

      {/* 4 Metric Summary Cards */}
      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        {filteredData.metrics.map((metric) => (
          <MetricCard key={metric.label} metric={metric} />
        ))}
      </div>

      {/* Main Row: Security Score, Severity Bar Chart, Orion AI Assistant */}
      <div className="mt-6 grid gap-6 xl:grid-cols-[1.08fr_1.08fr_0.96fr]">
        <SectionCard title="Security Score" eyebrow="Threat Posture" className="min-h-[506px]" contentClassName="pt-2">
          <SecurityDonutChart score={filteredData.securityScore} />
          <div className="mt-4 grid grid-cols-2 gap-3">
            <InfoTile label="Risk Level" value={filteredData.riskLevel} valueClassName={filteredData.riskColor} />
            <InfoTile
              label="Target Domain"
              value={filteredData.targetLabel}
              onClick={() => setIsTargetModalOpen(true)}
              className="border-cyan-500/30 hover:border-cyan-400 shadow-sm"
              valueClassName="text-cyan-500 font-mono text-[14px]"
            />
            <InfoTile label="Last Scan" value={filteredData.latestScan} />
            <InfoTile label="Scan Duration" value={filteredData.scanDuration} />
          </div>
        </SectionCard>

        <SectionCard title="Severity Distribution" subtitle={selectedDomain === "all" ? "Open findings by severity" : `Findings for ${selectedDomain}`} className="min-h-[506px]" contentClassName="pt-1">
          <SeverityBarChart data={filteredData.severity} onBarClick={handleSeverityClick} />
        </SectionCard>

        <AiPanel
          risks={filteredData.risks}
          messages={data.assistantMessages as AssistantMessage[]}
          defaultMessage={aiDefaultMessage}
          domains={selectedDomain === "all" ? allDomains : [selectedDomain]}
          vulnerabilities={filteredData.vulnerabilities}
        />
      </div>

      {/* Secondary Row: Activity, Scan Status, Coverage Radar, Attack Vectors, CVSS */}
      <div className="mt-6 grid gap-6 xl:grid-cols-[1.5fr_0.96fr]">
        <div className="space-y-6">
          <SectionCard title="Detection Activity" subtitle={selectedDomain === "all" ? "7-day detection activity" : `Activity for ${selectedDomain}`} className="min-h-[350px]" contentClassName="pt-3">
            <ActivityTrendChart data={filteredData.activity} />
          </SectionCard>
          <SectionCard title="Scan Status Overview" subtitle={selectedDomain === "all" ? "All-time scan results" : `Scan results for ${selectedDomain}`} icon={<SettingsIcon className="h-5 w-5" />} className="min-h-[382px]" contentClassName="pt-1">
            <StatusDonutChart data={filteredData.status} />
          </SectionCard>
        </div>

        <div className="space-y-6">
          <SectionCard title="Security Coverage" subtitle="Posture score by domain" icon={<Shield className="h-5 w-5" />} className="min-h-[382px]" contentClassName="pt-2">
            <CoverageRadarChart data={data.coverage} />
          </SectionCard>
          <SectionCard title="Attack Vectors" subtitle={selectedDomain === "all" ? "Distribution by entry type" : `Vectors for ${selectedDomain}`} className="min-h-[365px]" contentClassName="pt-1">
            <AttackVectorChart data={filteredData.attacks} />
          </SectionCard>
          <SectionCard title="CVSS Distribution" subtitle={selectedDomain === "all" ? "Findings by score range" : `CVSS for ${selectedDomain}`} className="min-h-[365px]" contentClassName="pt-1">
            <CvssChart data={filteredData.cvss} onBarClick={handleSeverityClick} />
          </SectionCard>
        </div>
      </div>
    </motion.div>
  );
}