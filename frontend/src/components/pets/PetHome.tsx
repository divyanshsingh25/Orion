/**
 * Orion Hacker Pets — PetHome
 *
 * Cute 2D SVG house that renders inline in the topbar via React portal.
 * Features animated door, window glow when pets are inside, and a subtle
 * cyberpunk antenna.
 */

import { memo, useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/utils/cn";

interface PetHomeProps {
  onClick: () => void;
  doorOpen: boolean;
  petsInside: boolean;
}

const PetHome = memo(function PetHome({ onClick, doorOpen, petsInside }: PetHomeProps) {
  const [mountEl, setMountEl] = useState<HTMLElement | null>(null);

  useEffect(() => {
    const findMount = () => {
      const el = document.getElementById("pet-home-mount");
      if (el) {
        setMountEl(el);
      } else {
        requestAnimationFrame(findMount);
      }
    };
    findMount();
  }, []);

  const homeContent = (
    <div
      className="orion-home-inline"
      onClick={onClick}
      role="button"
      title={petsInside ? "Pets are in their home! Click to call them out" : "Click to send pets back into their home"}
      aria-label={petsInside ? "Click to let pets out of Orion Home" : "Click to call pets to Orion Home"}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
    >
      <svg
        width="50"
        height="54"
        viewBox="0 0 90 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        style={{ display: "block", overflow: "visible" }}
      >
        {/* Ground shadow */}
        <ellipse cx="45" cy="95" rx="36" ry="4.5" fill="rgba(0,0,0,0.12)" />

        {/* House body */}
        <rect x="16" y="46" width="58" height="46" rx="5" fill="#1e293b" />

        {/* Wall shading */}
        <rect x="16" y="46" width="58" height="46" rx="5" fill="url(#homeWallGrad)" opacity="0.35" />

        {/* Brickwork subtle texture */}
        <line x1="16" y1="58" x2="74" y2="58" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
        <line x1="16" y1="70" x2="74" y2="70" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
        <line x1="16" y1="82" x2="74" y2="82" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />

        {/* === Roof === */}
        <path
          d="M6 49 L45 14 L84 49 Z"
          fill="#0f172a"
          stroke="#334155"
          strokeWidth="1"
          strokeLinejoin="round"
        />
        {/* Roof highlight */}
        <path d="M16 47 L45 20 L74 47" fill="none" stroke="#0ea5e9" strokeWidth="0.5" opacity="0.35" />

        {/* === Antenna === */}
        <line x1="63" y1="28" x2="63" y2="10" stroke="#475569" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="63" cy="8" r="2.5" fill="#0ea5e9" opacity="0.8" className="home-glow" />
        {/* Antenna signal rings */}
        <circle cx="63" cy="8" r="5" fill="none" stroke="#0ea5e9" strokeWidth="0.4" opacity="0.2" className="home-glow" />

        {/* === Left window === */}
        <rect x="22" y="54" width="14" height="12" rx="2.5" fill="#0c1929" stroke="#334155" strokeWidth="0.8" />
        {/* Window panes */}
        <line x1="29" y1="54" x2="29" y2="66" stroke="#334155" strokeWidth="0.5" />
        <line x1="22" y1="60" x2="36" y2="60" stroke="#334155" strokeWidth="0.5" />
        {/* Window glow when pets inside */}
        {petsInside && (
          <rect x="23" y="55" width="12" height="10" rx="2" fill="#fbbf24" opacity="0.65" className="home-glow" />
        )}
        {/* Curtains */}
        <line x1="23" y1="55" x2="23" y2="60" stroke="#475569" strokeWidth="0.5" opacity="0.5" />
        <line x1="35" y1="55" x2="35" y2="60" stroke="#475569" strokeWidth="0.5" opacity="0.5" />

        {/* === Right window === */}
        <rect x="54" y="54" width="14" height="12" rx="2.5" fill="#0c1929" stroke="#334155" strokeWidth="0.8" />
        <line x1="61" y1="54" x2="61" y2="66" stroke="#334155" strokeWidth="0.5" />
        <line x1="54" y1="60" x2="68" y2="60" stroke="#334155" strokeWidth="0.5" />
        {petsInside && (
          <rect x="55" y="55" width="12" height="10" rx="2" fill="#fbbf24" opacity="0.65" className="home-glow" />
        )}
        <line x1="55" y1="55" x2="55" y2="60" stroke="#475569" strokeWidth="0.5" opacity="0.5" />
        <line x1="67" y1="55" x2="67" y2="60" stroke="#475569" strokeWidth="0.5" opacity="0.5" />

        {/* === Door === */}
        <rect x="35" y="66" width="20" height="26" rx="2.5" fill="#0c1929" stroke="#334155" strokeWidth="1" />

        {/* Door panel (animated) */}
        <AnimatePresence>
          {!doorOpen && (
            <motion.g
              initial={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
            >
              <rect
                x="36"
                y="67"
                width="18"
                height="24"
                rx="2"
                fill="#1e3a5f"
              />
              {/* Door panels */}
              <rect x="38" y="69" width="14" height="8" rx="1" fill="rgba(255,255,255,0.03)" />
              <rect x="38" y="79" width="14" height="8" rx="1" fill="rgba(255,255,255,0.03)" />
              {/* Handle */}
              <circle cx="50" cy="80" r="1.8" fill="#64748b" stroke="#94a3b8" strokeWidth="0.3" />
              {/* Keyhole */}
              <circle cx="50" cy="82.5" r="0.6" fill="#0f172a" />
            </motion.g>
          )}
        </AnimatePresence>

        {/* Door glow when open */}
        {doorOpen && (
          <rect x="36" y="67" width="18" height="24" rx="2" fill="#0ea5e9" opacity="0.08" />
        )}

        {/* === Orion "O" emblem above door === */}
        <circle cx="45" cy="72" r="0" fill="none" />
        {!doorOpen && (
          <g opacity="0.4">
            <circle cx="45" cy="64" r="3" fill="none" stroke="#0ea5e9" strokeWidth="0.6" />
            <circle cx="45" cy="64" r="1" fill="#0ea5e9" opacity="0.4" />
          </g>
        )}

        {/* === Welcome mat === */}
        <rect x="33" y="90" width="24" height="3" rx="1.5" fill="#334155" opacity="0.6" />

        {/* Gradient defs */}
        <defs>
          <linearGradient id="homeWallGrad" x1="16" y1="46" x2="16" y2="92">
            <stop offset="0%" stopColor="#475569" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#0f172a" stopOpacity="0.1" />
          </linearGradient>
        </defs>
      </svg>

      <span
        className={cn(
          "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-extrabold tracking-wider uppercase transition-all shadow-sm select-none",
          petsInside
            ? "bg-amber-100 dark:bg-amber-950/80 border border-amber-300 dark:border-amber-700/70 text-amber-900 dark:text-amber-200"
            : "bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200"
        )}
      >
        <span
          className={cn(
            "h-2 w-2 rounded-full shrink-0",
            petsInside
              ? "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.9)] animate-pulse"
              : "bg-sky-500 shadow-[0_0_8px_rgba(14,165,233,0.7)]"
          )}
        />
        <span>{petsInside ? "Pets Inside" : "Home"}</span>
      </span>
    </div>
  );

  if (mountEl) {
    return createPortal(homeContent, mountEl);
  }

  // Fallback fixed position
  return (
    <div style={{ position: "fixed", right: 32, top: 130, zIndex: 9997, pointerEvents: "auto" }}>
      {homeContent}
    </div>
  );
});

export { PetHome };
