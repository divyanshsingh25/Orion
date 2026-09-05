import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

function scoreLabel(score: number): string {
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 50) return "Fair";
  if (score >= 25) return "Poor";
  return "Critical";
}

function scoreLabelColor(score: number): string {
  if (score >= 90) return "bg-emerald-500/[0.12] text-emerald-500 border border-emerald-500/25";
  if (score >= 75) return "bg-cyan-500/[0.12] text-cyan-500 border border-cyan-500/25";
  if (score >= 50) return "bg-amber-500/[0.12] text-amber-500 border border-amber-500/25";
  if (score >= 25) return "bg-orange-500/[0.12] text-orange-500 border border-orange-500/25";
  return "bg-red-500/[0.12] text-red-500 border border-red-500/25";
}

interface SecurityDonutChartProps {
  score?: number;
}

const RADIUS = 92;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS; // ~578.05

export function SecurityDonutChart({ score = 100 }: SecurityDonutChartProps) {
  const targetScore = Math.round(Math.max(0, Math.min(100, score)));
  const [displayScore, setDisplayScore] = useState<number>(targetScore);
  const textRef = useRef<HTMLDivElement>(null);
  const startValRef = useRef<number>(targetScore);

  useEffect(() => {
    const startVal = startValRef.current;
    const endVal = targetScore;
    startValRef.current = targetScore;

    if (startVal === endVal) {
      setDisplayScore(endVal);
      if (textRef.current) textRef.current.textContent = String(endVal);
      return;
    }

    const startTime = performance.now();
    const duration = 650;

    let frameId: number;

    const animateCount = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      const ease = 1 - Math.pow(1 - progress, 4);
      const current = Math.round(startVal + (endVal - startVal) * ease);

      if (textRef.current) {
        textRef.current.textContent = String(current);
      }

      if (progress < 1) {
        frameId = requestAnimationFrame(animateCount);
      } else {
        setDisplayScore(endVal);
        if (textRef.current) textRef.current.textContent = String(endVal);
      }
    };

    frameId = requestAnimationFrame(animateCount);
    return () => cancelAnimationFrame(frameId);
  }, [targetScore]);

  const strokeDashoffset = CIRCUMFERENCE - (CIRCUMFERENCE * targetScore) / 100;
  const currentLabel = scoreLabel(targetScore);
  const currentLabelColor = scoreLabelColor(targetScore);

  return (
    <div className="relative mx-auto mt-2 h-[240px] w-[240px]">
      <svg className="h-full w-full" viewBox="0 0 240 240">
        <defs>
          <linearGradient id="scoreRing" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="50%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#10b981" />
          </linearGradient>
        </defs>

        {/* Background Track */}
        <circle
          cx="120"
          cy="120"
          r={RADIUS}
          fill="none"
          stroke="currentColor"
          className="text-slate-200/80 dark:text-slate-800/80"
          strokeWidth="24"
        />

        {/* Hardware-Accelerated Progress Ring */}
        <circle
          cx="120"
          cy="120"
          r={RADIUS}
          fill="none"
          stroke="url(#scoreRing)"
          strokeWidth="24"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={strokeDashoffset}
          transform="rotate(-90 120 120)"
          style={{
            transition: "stroke-dashoffset 0.65s cubic-bezier(0.16, 1, 0.3, 1)",
          }}
        />
      </svg>

      {/* Centered Score & Rating */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-1 pointer-events-none">
        <div
          ref={textRef}
          className="text-[62px] font-bold leading-none tracking-[-0.04em] font-mono text-foreground select-none"
        >
          {displayScore}
        </div>
        <AnimatePresence mode="wait">
          <motion.div
            key={currentLabel}
            initial={{ opacity: 0, y: 3, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -3, scale: 0.95 }}
            transition={{ duration: 0.18 }}
            className={`mt-2 rounded-full px-3.5 py-1 text-[12px] font-bold uppercase tracking-[0.14em] shadow-sm ${currentLabelColor}`}
          >
            {currentLabel}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}