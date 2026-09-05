import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cable, Globe2, LockKeyhole, Server, ShieldCheck, Workflow } from "lucide-react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { ProgressBar } from "@/components/ui/progress";
import { getDashboardData } from "@/services/api";
import type { AttackSurfaceAsset } from "@/types/dashboard";
import { cn } from "@/utils/cn";

const riskTone = { Critical: "critical", High: "high", Medium: "medium", Low: "low" } as const;

export function AttackSurfacePage() {
  const { data } = useQuery({ queryKey: ["attack-surface"], queryFn: getDashboardData });
  const assets = (data?.attackSurfaceAssets ?? []) as AttackSurfaceAsset[];
  const [selected, setSelected] = useState(assets[0]?.name ?? "");
  const [tlsModalOpen, setTlsModalOpen] = useState(false);
  const activeAsset = assets.find((asset) => asset.name === selected) ?? assets[0];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div>
        <div className="section-label mb-3">External Exposure</div>
        <h1 className="text-[38px] font-bold leading-none tracking-[-0.03em]">Attack Surface</h1>
        <p className="muted-copy mt-4">Internet-facing assets, endpoints, ports, certificates, technologies, and exposure paths.</p>
      </div>

      <div className="mt-7 grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <section className="grid gap-4">
          {assets.map((asset) => (
            <button key={asset.name} type="button" onClick={() => setSelected(asset.name)} className={cn("panel p-5 text-left transition duration-300 hover:-translate-y-1", selected === asset.name && "border-cyan-300/70 shadow-[0_24px_70px_rgba(14,165,233,0.16)]")}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-[15px] bg-cyan-400/[0.12] text-cyan-500"><Globe2 className="h-6 w-6" /></div>
                  <div>
                    <h2 className="text-[18px] font-bold">{asset.name}</h2>
                    <p className="mt-1 text-[14px] font-bold text-muted-foreground">{asset.type} - {asset.endpoints} endpoints</p>
                  </div>
                </div>
                <Badge tone={riskTone[asset.risk]}>{asset.risk}</Badge>
              </div>
              <div className="mt-5 grid grid-cols-3 gap-3 text-[13px] font-bold text-muted-foreground">
                <div className="rounded-[14px] border border-border/70 bg-background/[0.55] p-3"><Server className="mb-2 h-4 w-4 text-cyan-500" />Ports {asset.ports.join(", ")}</div>
                <div className="rounded-[14px] border border-border/70 bg-background/[0.55] p-3"><Cable className="mb-2 h-4 w-4 text-cyan-500" />{asset.subdomains.length} subdomains</div>
                <div className="rounded-[14px] border border-border/70 bg-background/[0.55] p-3"><ShieldCheck className="mb-2 h-4 w-4 text-cyan-500" />{asset.exposure}% exposure</div>
              </div>
              <ProgressBar value={asset.exposure} tone={asset.risk === "Critical" ? "red" : asset.risk === "High" ? "amber" : "cyan"} className="mt-4" />
            </button>
          ))}
        </section>

        <section className="panel overflow-hidden p-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-[22px] font-bold">Exposure Graph</h2>
              <p className="mt-2 text-[15px] font-semibold text-muted-foreground">Interactive asset relationship map</p>
            </div>
            <Badge tone={riskTone[activeAsset?.risk ?? "Low"]}>{activeAsset?.risk}</Badge>
          </div>

          <div className="relative mt-6 h-[340px] overflow-hidden rounded-[22px] border border-border/70 bg-[#06111f] p-6 text-white">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_38%,rgba(34,211,238,0.22),transparent_24rem)]" />
            <div className="absolute left-1/2 top-1/2 z-10 flex h-24 w-24 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-cyan-300/40 bg-cyan-400/15 shadow-[0_0_70px_rgba(34,211,238,0.35)]"><Workflow className="h-9 w-9 text-cyan-300" /></div>
            
            {/* Dynamic SVG Connecting Lines */}
            <svg className="absolute inset-0 h-full w-full pointer-events-none z-0">
              {assets.map((asset, index) => {
                const total = assets.length || 1;
                const angle = (index * 2 * Math.PI) / total - Math.PI / 2; // start from top
                // X/Y coordinates as percentages of container width/height
                const targetX = 50 + Math.cos(angle) * 38;
                const targetY = 50 + Math.sin(angle) * 32;
                return (
                  <line
                    key={`line-${asset.name}`}
                    x1="50%"
                    y1="50%"
                    x2={`${targetX}%`}
                    y2={`${targetY}%`}
                    stroke="rgba(34, 211, 238, 0.25)"
                    strokeWidth="1.5"
                    strokeDasharray="4 4"
                  />
                );
              })}
            </svg>

            {/* Dynamic Asset Nodes */}
            {assets.map((asset, index) => {
              const total = assets.length || 1;
              const angle = (index * 2 * Math.PI) / total - Math.PI / 2;
              const leftPercent = 50 + Math.cos(angle) * 38;
              const topPercent = 50 + Math.sin(angle) * 32;

              return (
                <button
                  key={asset.name}
                  type="button"
                  onClick={() => setSelected(asset.name)}
                  className={cn(
                    "absolute z-20 rounded-[16px] border px-4 py-3 text-left transition hover:scale-105 -translate-x-1/2 -translate-y-1/2",
                    selected === asset.name ? "border-cyan-300 bg-cyan-400/20 shadow-[0_0_15px_rgba(34,211,238,0.25)]" : "border-white/10 bg-white/[0.08]"
                  )}
                  style={{
                    left: `${leftPercent}%`,
                    top: `${topPercent}%`
                  }}
                > 
                  <div className="font-mono text-[12px] font-bold whitespace-nowrap">{asset.name}</div>
                  <div className="mt-1 text-[10px] text-slate-400 uppercase tracking-wider">{asset.type}</div>
                </button>
              );
            })}
          </div>

          {activeAsset && (
            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div className="thin-panel p-4"><div className="section-label mb-3">Technologies</div><div className="flex flex-wrap gap-2">{Array.from(new Set(activeAsset.technologies)).map((tech) => <span key={tech} className="rounded-full border border-border/70 bg-background/60 px-3 py-1.5 text-[13px] font-bold">{tech}</span>)}</div></div>
              <button type="button" onClick={() => setTlsModalOpen(true)} className="thin-panel p-4 text-left transition hover:border-cyan-500/50 hover:bg-card/80">
                <div className="section-label mb-3">Certificate</div>
                <div className="flex items-center gap-2 text-[15px] font-bold">
                  {activeAsset.certificate.includes("HTTP") ? <Globe2 className="h-4 w-4 text-amber-500" /> : <LockKeyhole className="h-4 w-4 text-emerald-500" />}
                  {activeAsset.certificate}
                </div>
              </button>
              <div className="thin-panel p-4 lg:col-span-2"><div className="section-label mb-3">Subdomains</div><div className="grid gap-2 md:grid-cols-2">{activeAsset.subdomains.map((subdomain) => <div key={subdomain} className="rounded-[12px] border border-border/70 bg-background/60 px-3 py-2 font-mono text-[13px] font-bold">{subdomain}</div>)}</div></div>
            </div>
          )}
        </section>
      </div>

      {tlsModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={() => setTlsModalOpen(false)}>
          <div className="w-full max-w-md rounded-[20px] border border-border/70 bg-card p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="mb-6 flex items-center gap-3">
              <LockKeyhole className="h-6 w-6 text-emerald-500" />
              <h2 className="text-[20px] font-bold">TLS Certificate</h2>
            </div>
            <div className="space-y-4">
              <div className="rounded-[14px] bg-background/50 p-4">
                <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.12em] text-muted-foreground">Subject</div>
                <div className="text-[14px] font-medium break-all">{activeAsset.certificate_subject || "Not detected"}</div>
              </div>
              <div className="rounded-[14px] bg-background/50 p-4">
                <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.12em] text-muted-foreground">Issuer</div>
                <div className="text-[14px] font-medium break-all">{activeAsset.certificate_issuer || "Not detected"}</div>
              </div>
              <div className="rounded-[14px] bg-background/50 p-4">
                <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.12em] text-muted-foreground">Valid Until</div>
                <div className="text-[14px] font-medium break-all">{activeAsset.certificate_expiry || "Not detected"}</div>
              </div>
            </div>
            <button type="button" onClick={() => setTlsModalOpen(false)} className="mt-6 w-full rounded-[14px] bg-cyan-500 py-3 text-[14px] font-bold text-white transition hover:bg-cyan-600">Close</button>
          </div>
        </div>
      )}
    </motion.div>
  );
}