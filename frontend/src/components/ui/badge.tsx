import * as React from "react";
import { cn } from "@/utils/cn";

type BadgeTone = "critical" | "high" | "medium" | "low" | "success" | "running" | "failed" | "neutral";

const tones: Record<BadgeTone, string> = {
  critical: "border-red-400/30 bg-red-500/[0.12] text-red-500",
  high: "border-orange-400/30 bg-orange-500/[0.12] text-orange-500",
  medium: "border-amber-400/35 bg-amber-500/[0.14] text-amber-600 dark:text-amber-400",
  low: "border-sky-400/30 bg-sky-500/[0.12] text-sky-500",
  success: "border-emerald-400/30 bg-emerald-500/[0.12] text-emerald-500",
  running: "border-cyan-400/30 bg-cyan-500/[0.12] text-cyan-500",
  failed: "border-red-400/30 bg-red-500/[0.12] text-red-500",
  neutral: "border-slate-400/25 bg-slate-500/10 text-slate-500 dark:text-slate-300",
};

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

export function Badge({ className, tone = "success", ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex h-[27px] items-center rounded-full border px-2.5 text-[12px] font-bold uppercase tracking-[0.02em]",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}