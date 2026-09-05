import { cn } from "@/utils/cn";
import { motion } from "framer-motion";

interface ProgressBarProps {
  value: number;
  tone?: "cyan" | "green" | "amber" | "red" | "blue";
  className?: string;
}

const tones = {
  cyan: "from-cyan-400 to-blue-500",
  green: "from-emerald-400 to-cyan-400",
  amber: "from-amber-400 to-orange-500",
  red: "from-red-500 to-orange-500",
  blue: "from-blue-500 to-indigo-500",
};

export function ProgressBar({ value, tone = "cyan", className }: ProgressBarProps) {
  return (
    <div className={cn("h-2.5 w-full overflow-hidden rounded-full bg-slate-200/70 dark:bg-slate-800/80 border border-slate-300/40 dark:border-slate-700/40", className)}>
      <motion.div
        className={cn("h-full rounded-full bg-gradient-to-r shadow-sm", tones[tone])}
        initial={{ width: 0 }}
        animate={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        transition={{ duration: 0.8, ease: "easeOut" }}
      />
    </div>
  );
}