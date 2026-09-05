import { TrendingDown, TrendingUp } from "lucide-react";
import type { Metric } from "@/types/dashboard";
import { cn } from "@/utils/cn";

const accents: Record<Metric["accent"], string> = {
  cyan: "from-cyan-500/[0.18] to-blue-500/[0.08] border-cyan-400/25",
  purple: "from-indigo-500/[0.16] to-cyan-500/[0.08] border-indigo-400/25",
  red: "from-red-500/[0.16] to-orange-500/[0.08] border-red-400/25",
  orange: "from-orange-500/[0.16] to-amber-500/[0.08] border-orange-400/25",
  yellow: "from-amber-500/[0.16] to-yellow-400/[0.08] border-amber-400/25",
};

const iconTone: Record<Metric["accent"], string> = {
  cyan: "text-cyan-500 bg-cyan-500/[0.12]",
  purple: "text-indigo-500 bg-indigo-500/[0.12]",
  red: "text-red-500 bg-red-500/[0.12]",
  orange: "text-orange-500 bg-orange-500/[0.12]",
  yellow: "text-amber-500 bg-amber-500/[0.12]",
};

export function MetricCard({ metric }: { metric: Metric }) {
  const alert = metric.label === "Medium" || metric.label === "Critical";

  return (
    <div className={cn("top-card group relative h-[124px] overflow-hidden border bg-gradient-to-br px-5 py-4 transition duration-300 hover:-translate-y-1 hover:shadow-[0_24px_60px_rgba(15,23,42,0.14)]", accents[metric.accent])}>
      <div className="absolute right-0 top-0 h-24 w-24 rounded-bl-full bg-white/30 blur-2xl dark:bg-white/5" />
      <div className="relative flex items-start justify-between">
        <div>
          <div className="section-label text-[11px]">{metric.label}</div>
          <div className="mt-3 text-[46px] font-bold leading-none tracking-[-0.02em]">{metric.value}</div>
        </div>
        <div className={cn("flex h-9 items-center gap-1.5 rounded-full px-3 text-[12px] font-bold", alert ? "bg-red-500/[0.12] text-red-500" : "bg-emerald-500/[0.12] text-emerald-500")}>
          {metric.trend === "up" ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
          {metric.delta}
        </div>
      </div>
      <div className="relative mt-3 flex items-center justify-end text-[12px] font-bold text-muted-foreground">
      </div>
    </div>
  );
}