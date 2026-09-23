import { useMemo, useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Calendar, Download, FileCheck, FileText, Globe, Layers, Presentation, Search, ShieldCheck, Trash2, Sparkles, X } from "lucide-react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ProgressBar } from "@/components/ui/progress";
import { downloadReport, getDashboardData, deleteReport, generateReport } from "@/services/api";
import type { ReportItem } from "@/types/dashboard";
import { cn } from "@/utils/cn";

function parseReportMeta(name: string) {
  const clean = name.replace(/\.(pdf|html)$/i, "");
  const parts = clean.split("_");
  const target = parts[0] || name;
  return { target, fullName: name };
}

function getScoreDetails(rawScore: number) {
  const riskScore = Math.max(0, Math.min(100, rawScore || 0));
  const postureScore = Math.max(0, 100 - riskScore);

  if (riskScore <= 25) {
    return {
      posture: postureScore,
      riskScore,
      riskLevel: "Low Risk",
      tone: "success" as const,
      progressTone: "green" as const,
      statusClass: "text-emerald-500 bg-emerald-500/10 border-emerald-500/25",
    };
  }
  if (riskScore <= 55) {
    return {
      posture: postureScore,
      riskScore,
      riskLevel: "Moderate Risk",
      tone: "medium" as const,
      progressTone: "amber" as const,
      statusClass: "text-amber-500 bg-amber-500/10 border-amber-500/25",
    };
  }
  return {
    posture: postureScore,
    riskScore,
    riskLevel: "Elevated Risk",
    tone: "critical" as const,
    progressTone: "red" as const,
    statusClass: "text-rose-500 bg-rose-500/10 border-rose-500/25",
  };
}

export function ReportsPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSearch = searchParams.get("search") || searchParams.get("q") || "";
  const [searchQuery, setSearchQuery] = useState(urlSearch);

  const { data } = useQuery({ queryKey: ["reports"], queryFn: getDashboardData });
  const reports = (data?.reports ?? []) as ReportItem[];
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    setSearchQuery(urlSearch);
  }, [urlSearch]);

  const handleSearchChange = (val: string) => {
    setSearchQuery(val);
    if (val.trim()) {
      setSearchParams({ search: val.trim() }, { replace: true });
    } else {
      setSearchParams({}, { replace: true });
    }
  };

  const filteredReports = useMemo(() => {
    if (!searchQuery.trim()) return reports;
    const q = searchQuery.toLowerCase().trim();
    return reports.filter((r) => {
      const meta = parseReportMeta(r.name);
      return (
        meta.target.toLowerCase().includes(q) ||
        r.name.toLowerCase().includes(q) ||
        r.type.toLowerCase().includes(q) ||
        r.status.toLowerCase().includes(q) ||
        r.updated.toLowerCase().includes(q) ||
        (r.audience && r.audience.toLowerCase().includes(q))
      );
    });
  }, [reports, searchQuery]);

  const activeReport = (selectedId ? filteredReports.find((r) => (r.id || r.name) === selectedId) : null) || filteredReports[0] || reports[0];
  const activeMeta = activeReport ? parseReportMeta(activeReport.name) : null;
  const activeScore = activeReport ? getScoreDetails(activeReport.score) : null;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="pb-32">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="section-label mb-3">Executive Outputs</div>
          <h1 className="text-[38px] font-bold leading-none tracking-[-0.03em]">Security Reports</h1>
          <p className="muted-copy mt-4">Board-ready risk reports, engineering remediation plans, and exportable assessment packs.</p>
        </div>
        {activeReport && (
          <div className="flex gap-3">
            <Button
              className="h-10 px-4 font-semibold"
              disabled={!activeReport.id && !activeReport.scan_id}
              onClick={async () => {
                if (activeReport.id) {
                  downloadReport(activeReport.id, `${activeReport.name}.pdf`);
                } else if (activeReport.scan_id) {
                  const gen = await generateReport(activeReport.scan_id, "pdf");
                  if (gen?.id) downloadReport(gen.id, `${activeReport.name}.pdf`);
                  queryClient.invalidateQueries({ queryKey: ["reports"] });
                }
              }}
            >
              <Download className="h-4 w-4" />
              Export PDF
            </Button>
            <Button
              variant="outline"
              className="h-10 px-4 font-semibold"
              disabled={!activeReport.scan_id}
              onClick={() =>
                activeReport.scan_id &&
                generateReport(activeReport.scan_id, "html").then((r) => downloadReport(r.id, `${activeReport.name}.html`))
              }
            >
              <Globe className="h-4 w-4" />
              Export HTML
            </Button>
          </div>
        )}
      </div>

      <div className="mt-7 grid gap-6 xl:grid-cols-[1fr_1.15fr] items-start">
        {/* Left Column: Report List */}
        <section className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-1">
            <h2 className="text-[17px] font-bold text-muted-foreground uppercase tracking-wider">
              {searchQuery.trim() ? (
                <>Search Results ({filteredReports.length} of {reports.length})</>
              ) : (
                <>Generated Reports ({reports.length})</>
              )}
            </h2>
            <span className="text-[13px] text-muted-foreground">
              {filteredReports.length > 0 ? "Select a report to preview" : "No matching reports"}
            </span>
          </div>

          {/* Search Input Filter */}
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Search all reports by target, filename, date, or status..."
              className="h-11 w-full rounded-[14px] border border-border/70 bg-card/60 pl-10 pr-10 text-[14px] font-medium text-foreground placeholder:text-muted-foreground shadow-sm transition focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/20"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => handleSearchChange("")}
                className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-1 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                title="Clear search"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>

          {reports.length === 0 ? (
            <div className="panel p-8 text-center text-muted-foreground">
              <FileText className="mx-auto h-12 w-12 opacity-30" />
              <h3 className="mt-3 text-[16px] font-bold text-foreground">No reports generated yet</h3>
              <p className="mt-1 text-[13px]">Launch a security assessment to generate automated board reports.</p>
            </div>
          ) : filteredReports.length === 0 ? (
            <div className="panel p-8 text-center text-muted-foreground">
              <FileText className="mx-auto h-12 w-12 opacity-30" />
              <h3 className="mt-3 text-[16px] font-bold text-foreground">No reports matching "{searchQuery}"</h3>
              <p className="mt-1 text-[13px]">Try searching with a different domain, keyword, or clear the search filter.</p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 gap-1.5"
                onClick={() => handleSearchChange("")}
              >
                <X className="h-3.5 w-3.5" />
                Clear search filter
              </Button>
            </div>
          ) : (
            filteredReports.map((report) => {
              const meta = parseReportMeta(report.name);
              const scoreInfo = getScoreDetails(report.score);
              const isSelected = activeReport?.name === report.name;

              return (
                <div
                  key={report.id || report.name}
                  onClick={() => setSelectedId(report.id || report.name)}
                  className={cn(
                    "panel p-5 transition-all duration-200 cursor-pointer border",
                    isSelected
                      ? "border-cyan-500/60 bg-cyan-500/[0.04] shadow-lg shadow-cyan-950/20 ring-1 ring-cyan-500/30"
                      : "border-border/70 hover:border-cyan-400/40 hover:-translate-y-0.5"
                  )}
                >
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-[14px] border border-cyan-500/20 bg-cyan-500/[0.12] text-cyan-500">
                        <FileText className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <h2 className="text-[17px] font-bold truncate text-foreground">{meta.target}</h2>
                          <span className="rounded-md border border-border/80 bg-muted/60 px-1.5 py-0.5 text-[11px] font-mono font-semibold uppercase text-muted-foreground">
                            {report.type}
                          </span>
                        </div>
                        <p className="mt-0.5 text-[13px] font-medium text-muted-foreground truncate">{report.name}</p>
                      </div>
                    </div>
                    <Badge tone={report.status === "Ready" ? "success" : "running"} className="shrink-0">
                      {report.status}
                    </Badge>
                  </div>

                  {/* Refined Posture & Risk Indicator Strip */}
                  <div className="mt-4 rounded-[14px] border border-border/60 bg-muted/30 p-3.5">
                    <div className="flex items-center justify-between text-[13px] mb-2">
                      <span className="font-semibold text-muted-foreground">Security Posture</span>
                      <div className="flex items-center gap-2">
                        <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-bold", scoreInfo.statusClass)}>
                          {scoreInfo.riskLevel}
                        </span>
                        <span className="font-mono font-bold text-foreground">{scoreInfo.posture}%</span>
                      </div>
                    </div>
                    <ProgressBar value={scoreInfo.posture} tone={scoreInfo.progressTone} className="h-2" />
                  </div>

                  {/* Metadata Row */}
                  <div className="mt-3.5 flex flex-wrap items-center gap-y-1 gap-x-4 text-[12px] font-semibold text-muted-foreground">
                    <span className="inline-flex items-center gap-1.5">
                      <Calendar className="h-3.5 w-3.5 text-cyan-500" />
                      {report.updated}
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <FileCheck className="h-3.5 w-3.5 text-cyan-500" />
                      {report.pages} pages
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <Layers className="h-3.5 w-3.5 text-cyan-500" />
                      {report.audience} Scope
                    </span>
                  </div>

                  {/* Actions Row */}
                  <div className="mt-4 flex items-center justify-between border-t border-border/50 pt-3">
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 gap-1.5 text-[12px] px-3 font-semibold hover:border-cyan-400 hover:text-cyan-500"
                        disabled={!report.id}
                        onClick={(e) => {
                          e.stopPropagation();
                          if (report.id) downloadReport(report.id, `${report.name}.pdf`);
                        }}
                      >
                        <Download className="h-3.5 w-3.5 text-cyan-500" />
                        PDF
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 gap-1.5 text-[12px] px-3 font-semibold hover:border-cyan-400 hover:text-cyan-500"
                        disabled={!report.scan_id}
                        onClick={(e) => {
                          e.stopPropagation();
                          if (report.scan_id) {
                            generateReport(report.scan_id, "html").then((r) => downloadReport(r.id, `${report.name}.html`));
                          }
                        }}
                      >
                        <Globe className="h-3.5 w-3.5 text-cyan-500" />
                        HTML
                      </Button>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 w-8 p-0 text-muted-foreground hover:bg-rose-500/10 hover:text-rose-500 transition-colors"
                      title="Delete report"
                      disabled={!report.id}
                      onClick={async (e) => {
                        e.stopPropagation();
                        if (report.id) {
                          await deleteReport(report.id);
                          queryClient.invalidateQueries({ queryKey: ["reports"] });
                        }
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              );
            })
          )}
        </section>

        {/* Right Column: Live Report Preview */}
        <section className="panel overflow-y-auto sticky top-[96px] max-h-[calc(100vh-120px)]">
          <div className="border-b border-border/70 p-6 flex items-center justify-between">
            <div>
              <h2 className="text-[22px] font-bold">Executive Risk Brief</h2>
              <p className="mt-1 text-[14px] font-medium text-muted-foreground">
                Live document preview & board narrative
              </p>
            </div>
            {activeReport && (
              <Badge tone="success" className="gap-1 px-3 py-1">
                <Sparkles className="h-3.5 w-3.5 text-emerald-400" />
                {activeReport.status}
              </Badge>
            )}
          </div>

          <div className="p-6 space-y-6">
            {activeReport && activeMeta && activeScore ? (
              <div className="rounded-[20px] border border-border/80 bg-card/60 p-6 shadow-sm">
                {/* Document Header */}
                <div className="flex items-start justify-between border-b border-border/70 pb-5">
                  <div>
                    <div className="text-[12px] font-bold uppercase tracking-[0.16em] text-cyan-500">
                      ORION Enterprise Security
                    </div>
                    <h3 className="mt-1.5 text-[24px] font-bold tracking-tight text-foreground">
                      Security Assessment Brief
                    </h3>
                    <p className="mt-1 text-[13px] font-mono text-muted-foreground">
                      Target: <span className="text-foreground font-semibold">{activeMeta.target}</span> • {activeReport.updated}
                    </p>
                  </div>
                  <div className="flex h-12 w-12 items-center justify-center rounded-[16px] bg-cyan-500/[0.12] text-cyan-500 border border-cyan-500/25">
                    <ShieldCheck className="h-7 w-7" />
                  </div>
                </div>

                {/* Score Tiles */}
                <div className="mt-5 grid grid-cols-3 gap-3">
                  <div className="rounded-[14px] border border-border/60 bg-muted/30 p-3.5 text-center">
                    <div className="font-mono text-[22px] font-bold text-foreground leading-none">
                      {activeScore.posture}%
                    </div>
                    <div className="mt-1 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      Security Posture
                    </div>
                  </div>
                  <div className="rounded-[14px] border border-border/60 bg-muted/30 p-3.5 text-center">
                    <div className="font-mono text-[22px] font-bold text-cyan-500 leading-none">
                      {activeReport.pages}
                    </div>
                    <div className="mt-1 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      Report Pages
                    </div>
                  </div>
                  <div className="rounded-[14px] border border-border/60 bg-muted/30 p-3.5 text-center">
                    <div className={cn("font-mono text-[16px] font-bold leading-tight", activeScore.statusClass.split(" ")[0])}>
                      {activeScore.riskLevel}
                    </div>
                    <div className="mt-1 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      Risk Rating
                    </div>
                  </div>
                </div>

                {/* Narrative Text */}
                <div className="mt-5 space-y-3 text-[14px] font-medium leading-relaxed text-muted-foreground">
                  <p>
                    Target assessment for <strong className="text-foreground font-semibold">{activeMeta.target}</strong> completed with all reconnaissance, protocol fuzzing, and OWASP vulnerability test suites compiled.
                  </p>
                  <p>
                    Executive recommendation: Review critical and high findings, apply suggested patch guidance, and execute verification scans to maintain defensive SLA benchmarks.
                  </p>
                </div>

                {/* Board Narrative Banner */}
                <div className="mt-6 rounded-[16px] bg-gradient-to-r from-cyan-600 to-blue-700 p-5 text-white shadow-md">
                  <div className="flex items-center gap-2.5">
                    <Presentation className="h-5 w-5 text-cyan-200" />
                    <div className="text-[17px] font-bold">Board narrative & evidence appendix</div>
                  </div>
                  <div className="mt-1.5 text-[13px] font-medium text-cyan-50/90 leading-relaxed">
                    Includes finding correlation, OWASP/CWE breakdown, CVSS matrix, and AI-assisted remediation code.
                  </div>
                  <div className="mt-4 flex items-center gap-3">
                    <Button
                      size="sm"
                      className="h-9 px-4 bg-white text-slate-950 hover:bg-slate-100 font-bold border-none shadow-sm"
                      disabled={!activeReport.id}
                      onClick={() => activeReport.id && downloadReport(activeReport.id, `${activeReport.name}.pdf`)}
                    >
                      <Download className="h-4 w-4 mr-1.5 text-cyan-700" />
                      Download PDF
                    </Button>
                    {activeReport.scan_id && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-9 px-4 text-white border-white/30 hover:bg-white/10 font-bold"
                        onClick={() =>
                          generateReport(activeReport.scan_id!, "html").then((r) =>
                            downloadReport(r.id, `${activeReport.name}.html`))
                        }
                      >
                        <Globe className="h-4 w-4 mr-1.5" />
                        View HTML
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-muted-foreground">
                <p>Select a report from the list to preview details.</p>
              </div>
            )}
          </div>
        </section>
      </div>
    </motion.div>
  );
}