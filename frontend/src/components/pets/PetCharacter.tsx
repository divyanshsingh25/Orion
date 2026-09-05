/**
 * Orion Hacker Pets — PetCharacter
 *
 * Cute 2D SVG chibi-style hacker pet with:
 *  - Cursor-following via refs + RAF (zero React re-renders)
 *  - Collision detection against data-pet-obstacle="true" elements
 *  - Per-personality idle animations
 */

import { useRef, useEffect, useCallback, memo } from "react";
import type { PetConfig } from "./petConfig";
import { PET_SIZE } from "./petConfig";

interface PetCharacterProps {
  config: PetConfig;
  mouseRef: React.RefObject<{ x: number; y: number } | null>;
  isFollowing: boolean;
  targetPos: { x: number; y: number } | null;
  onArrived?: () => void;
  visible: boolean;
}

/* ─── Collision Helpers ───────────────────────────── */

const OBSTACLE_PADDING = 8; // px of safety margin around each obstacle (reduced so pets can navigate narrow paths)
const OBSTACLE_CACHE_MS = 150; // re-query DOM obstacles at most every 150ms

interface PaddedRect {
  left: number;
  right: number;
  top: number;
  bottom: number;
}

/** Cached obstacle rects to avoid querying DOM every frame */
let cachedObstacles: PaddedRect[] = [];
let lastObstacleQuery = 0;

function getObstacleRects(): PaddedRect[] {
  const now = performance.now();
  if (now - lastObstacleQuery < OBSTACLE_CACHE_MS) return cachedObstacles;
  lastObstacleQuery = now;

  const els = document.querySelectorAll<HTMLElement>("[data-pet-obstacle='true']");
  cachedObstacles = Array.from(els).map((el) => {
    const r = el.getBoundingClientRect();
    return {
      left: r.left - OBSTACLE_PADDING,
      right: r.right + OBSTACLE_PADDING,
      top: r.top - OBSTACLE_PADDING,
      bottom: r.bottom + OBSTACLE_PADDING,
    };
  });
  return cachedObstacles;
}

/** Returns true if the pet's bounding box overlaps any obstacle rect */
function overlapsAny(x: number, y: number, rects: PaddedRect[]): boolean {
  const petRight = x + PET_SIZE.width;
  const petBottom = y + PET_SIZE.height;
  for (const r of rects) {
    if (petRight > r.left && x < r.right && petBottom > r.top && y < r.bottom) {
      return true;
    }
  }
  return false;
}

/**
 * Push the pet position outside any overlapping obstacle.
 * Uses the smallest-penetration-depth axis to decide which side to resolve.
 */
function resolveCollisions(
  x: number,
  y: number,
  rects: PaddedRect[]
): { x: number; y: number } {
  let rx = x;
  let ry = y;

  for (const r of rects) {
    const petRight = rx + PET_SIZE.width;
    const petBottom = ry + PET_SIZE.height;

    if (petRight <= r.left || rx >= r.right || petBottom <= r.top || ry >= r.bottom) {
      continue; // no overlap
    }

    // Penetration depths on each axis
    const overlapLeft = petRight - r.left;   // push pet left
    const overlapRight = r.right - rx;        // push pet right
    const overlapTop = petBottom - r.top;     // push pet up
    const overlapBottom = r.bottom - ry;      // push pet down

    const minH = Math.min(overlapLeft, overlapRight);
    const minV = Math.min(overlapTop, overlapBottom);

    if (minH < minV) {
      // Resolve horizontally
      if (overlapLeft < overlapRight) {
        rx = r.left - PET_SIZE.width; // push left
      } else {
        rx = r.right; // push right
      }
    } else {
      // Resolve vertically
      if (overlapTop < overlapBottom) {
        ry = r.top - PET_SIZE.height; // push up
      } else {
        ry = r.bottom; // push down
      }
    }
  }

  return { x: rx, y: ry };
}

/* ─── SVG Pet Sprite ──────────────────────────────── */

function PetSvg({ config }: { config: PetConfig }) {
  const {
    hatColor,
    hatAccent,
    skinColor,
    bodyColor,
    eyeStyle,
    accessory,
    glowColor,
    id,
  } = config;

  const eyeW = eyeStyle === "calm" ? 5 : 5.5;
  const eyeH = eyeStyle === "calm" ? 4.5 : 5.5;
  const pupilR = eyeStyle === "calm" ? 1.8 : 2;
  const blinkClass =
    eyeStyle === "playful"
      ? "pet-blink-fast"
      : eyeStyle === "calm"
        ? "pet-blink-slow"
        : "pet-blink";
  const idleClass =
    eyeStyle === "playful"
      ? "pet-bounce-fast"
      : eyeStyle === "calm"
        ? "pet-sway"
        : "pet-float";

  return (
    <div className={idleClass}>
      <svg
        width={PET_SIZE.width}
        height={PET_SIZE.height}
        viewBox="0 0 56 68"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        {/* Ground glow */}
        <ellipse cx="28" cy="65" rx="16" ry="3" fill={glowColor} opacity="0.25" className="home-glow" />

        {/* Left leg */}
        <g className="pet-walk-left">
          <rect x="17" y="57" width="6" height="7" rx="3" fill={bodyColor} />
          <ellipse cx="20" cy="63" rx="4" ry="2.2" fill="#475569" />
        </g>

        {/* Right leg */}
        <g className="pet-walk-right">
          <rect x="33" y="57" width="6" height="7" rx="3" fill={bodyColor} />
          <ellipse cx="36" cy="63" rx="4" ry="2.2" fill="#475569" />
        </g>

        {/* Body */}
        <rect x="13" y="38" width="30" height="22" rx="8" fill={bodyColor} />
        <rect x="21" y="48" width="14" height="6" rx="3" fill="rgba(255,255,255,0.06)" />
        <path d="M20 39 Q28 43 36 39" stroke={hatAccent} strokeWidth="0.8" fill="none" opacity="0.5" />

        {/* Left arm (typing gesture) */}
        <g className="pet-typing">
          <rect x="7" y="40" width="8" height="14" rx="4" fill={bodyColor} />
          <circle cx="11" cy="54" r="3" fill={skinColor} />
        </g>

        {/* Right arm */}
        <rect x="41" y="40" width="8" height="14" rx="4" fill={bodyColor} />
        <circle cx="45" cy="54" r="3" fill={skinColor} />

        {/* Head */}
        <circle cx="28" cy="24" r="16" fill={skinColor} />
        <ellipse cx="28" cy="30" rx="12" ry="6" fill="rgba(0,0,0,0.04)" />

        {/* Cheek blush */}
        <ellipse cx="16" cy="29" rx="3.5" ry="2" fill="#ff9999" opacity="0.25" />
        <ellipse cx="40" cy="29" rx="3.5" ry="2" fill="#ff9999" opacity="0.25" />

        {/* Eyes (with blink animation) */}
        <g className={blinkClass} style={{ transformOrigin: "28px 26px" }}>
          <ellipse cx="22" cy="26" rx={eyeW} ry={eyeH} fill="#fff" />
          <ellipse cx="22" cy="26" rx={eyeW - 0.5} ry={eyeH - 0.5} fill="#fff" stroke="#c8ccd4" strokeWidth="0.3" />
          <ellipse cx="34" cy="26" rx={eyeW} ry={eyeH} fill="#fff" />
          <ellipse cx="34" cy="26" rx={eyeW - 0.5} ry={eyeH - 0.5} fill="#fff" stroke="#c8ccd4" strokeWidth="0.3" />
        </g>

        {/* Pupils (look-around animation) */}
        <g className="pet-look">
          <circle cx="23" cy="26.5" r={pupilR} fill="#1e293b" />
          <circle cx="23.8" cy="25.5" r="0.9" fill="#fff" />
          <circle cx="35" cy="26.5" r={pupilR} fill="#1e293b" />
          <circle cx="35.8" cy="25.5" r="0.9" fill="#fff" />
          <circle cx="23" cy="27" r="0.6" fill={hatAccent} opacity="0.5" />
          <circle cx="35" cy="27" r="0.6" fill={hatAccent} opacity="0.5" />
        </g>

        {/* Mouth */}
        {eyeStyle === "playful" && (
          <path d="M24 31.5 Q28 35 32 31.5" stroke="#6b7280" strokeWidth="0.9" fill="none" strokeLinecap="round" />
        )}
        {eyeStyle === "calm" && (
          <line x1="25" y1="32" x2="31" y2="32" stroke="#6b7280" strokeWidth="0.8" strokeLinecap="round" />
        )}
        {eyeStyle === "friendly" && (
          <>
            <path d="M24 31 Q28 34 32 31" stroke="#6b7280" strokeWidth="0.9" fill="none" strokeLinecap="round" />
            <ellipse cx="28" cy="33" rx="1.5" ry="1" fill="#fca5a5" opacity="0.5" />
          </>
        )}

        {/* Hat */}
        {renderHat(id, hatColor, hatAccent)}

        {/* Accessory */}
        {renderAccessory(accessory, hatAccent)}
      </svg>
    </div>
  );
}

/* ─── Hat variants ────────────────────────────────── */

function renderHat(id: string, color: string, accent: string) {
  if (id === "red-hat") {
    return (
      <g>
        <ellipse cx="28" cy="13" rx="17" ry="11" fill={color} />
        <rect x="12" y="13" width="32" height="5" rx="2.5" fill={color} />
        <rect x="13" y="15" width="30" height="2" rx="1" fill={accent} opacity="0.45" />
        <line x1="18" y1="8" x2="18" y2="14" stroke={accent} strokeWidth="0.4" opacity="0.2" />
        <line x1="23" y1="6" x2="23" y2="14" stroke={accent} strokeWidth="0.4" opacity="0.2" />
        <line x1="28" y1="5" x2="28" y2="14" stroke={accent} strokeWidth="0.4" opacity="0.2" />
        <line x1="33" y1="6" x2="33" y2="14" stroke={accent} strokeWidth="0.4" opacity="0.2" />
        <line x1="38" y1="8" x2="38" y2="14" stroke={accent} strokeWidth="0.4" opacity="0.2" />
        <circle cx="28" cy="4" r="3.5" fill={accent} />
        <circle cx="29" cy="3" r="1" fill="#fff" opacity="0.3" />
      </g>
    );
  }
  if (id === "black-hat") {
    return (
      <g>
        <path d="M11 17 Q11 3 28 2 Q45 3 45 17" fill={color} />
        <ellipse cx="28" cy="17" rx="18" ry="4.5" fill={color} />
        <path d="M15 16 Q15 8 28 6 Q41 8 41 16" fill="rgba(255,255,255,0.04)" />
        <rect x="14" y="14" width="28" height="2.5" rx="1.2" fill={accent} opacity="0.25" />
        <text x="28" y="12" textAnchor="middle" fill={accent} opacity="0.35" fontSize="5" fontFamily="monospace" fontWeight="700">
          &gt;_
        </text>
      </g>
    );
  }
  return (
    <g>
      <ellipse cx="28" cy="13" rx="17" ry="10.5" fill={color} />
      <ellipse cx="28" cy="17" rx="19" ry="4" fill={color} />
      <ellipse cx="28" cy="17.5" rx="17" ry="2.5" fill="rgba(0,0,0,0.06)" />
      <path d="M25 9 L28 6 L31 9 L31 13 Q28 15.5 25 13 Z" fill={accent} opacity="0.7" />
      <path d="M26.5 10 L28 8.5 L29.5 10 L29.5 12 Q28 13 26.5 12 Z" fill="#fff" opacity="0.4" />
      <circle cx="28" cy="4.5" r="1.8" fill={color} stroke="#cbd5e1" strokeWidth="0.4" />
    </g>
  );
}

/* ─── Accessory variants ──────────────────────────── */

function renderAccessory(type: string, accent: string) {
  if (type === "circuit") {
    return (
      <g>
        <rect x="3" y="49" width="10" height="7" rx="1.5" fill="#064e3b" stroke="#10b981" strokeWidth="0.5" />
        <line x1="5" y1="50.5" x2="5" y2="55" stroke="#34d399" strokeWidth="0.4" opacity="0.7" />
        <line x1="7.5" y1="50.5" x2="7.5" y2="55" stroke="#34d399" strokeWidth="0.4" opacity="0.7" />
        <line x1="10" y1="50.5" x2="10" y2="55" stroke="#34d399" strokeWidth="0.4" opacity="0.7" />
        <rect x="4" y="52" width="2" height="1.5" rx="0.3" fill="#10b981" opacity="0.6" />
        <rect x="8" y="51" width="2" height="1.5" rx="0.3" fill="#10b981" opacity="0.6" />
        <circle cx="6" cy="51" r="0.6" fill="#34d399" className="home-glow" />
      </g>
    );
  }
  if (type === "terminal") {
    return (
      <g>
        <rect x="38" y="47" width="13" height="9" rx="1.5" fill="#0f172a" stroke="#334155" strokeWidth="0.6" />
        <line x1="40" y1="49.5" x2="47" y2="49.5" stroke={accent} strokeWidth="0.5" opacity="0.8" />
        <line x1="40" y1="51.5" x2="45" y2="51.5" stroke="#22c55e" strokeWidth="0.5" opacity="0.6" />
        <line x1="40" y1="53.5" x2="48" y2="53.5" stroke="#94a3b8" strokeWidth="0.4" opacity="0.4" />
        <rect x="46" y="49" width="1" height="1.5" fill={accent} opacity="0.7" className="home-glow" />
        <rect x="38" y="56" width="13" height="2.5" rx="0.8" fill="#1e293b" stroke="#334155" strokeWidth="0.4" />
        <circle cx="41" cy="57.2" r="0.4" fill="#475569" />
        <circle cx="43" cy="57.2" r="0.4" fill="#475569" />
        <circle cx="45" cy="57.2" r="0.4" fill="#475569" />
        <circle cx="47" cy="57.2" r="0.4" fill="#475569" />
      </g>
    );
  }
  return (
    <g>
      <path d="M42 46 L48 48.5 L48 54 Q45 57.5 42 54 Z" fill={accent} opacity="0.2" stroke={accent} strokeWidth="0.8" />
      <path d="M43.5 48.5 L46.5 49.8 L46.5 53 Q45 54.5 43.5 53 Z" fill={accent} opacity="0.5" />
      <path d="M44 51 L45 52.2 L47 49.5" stroke="#fff" strokeWidth="0.7" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.7" />
    </g>
  );
}

function getInitialHomePos(offsetX: number) {
  if (typeof document !== "undefined") {
    const mount = document.getElementById("pet-home-mount");
    if (mount) {
      const rect = mount.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2 - PET_SIZE.width / 2 + offsetX,
        y: rect.bottom + 12,
      };
    }
  }
  return {
    x: (typeof window !== "undefined" ? window.innerWidth : 1024) - 120 + offsetX,
    y: 80,
  };
}

/* ─── PetCharacter Component ──────────────────────── */

const PetCharacter = memo(function PetCharacter({
  config,
  mouseRef,
  isFollowing,
  targetPos,
  onArrived,
  visible,
}: PetCharacterProps) {
  const elRef = useRef<HTMLDivElement>(null);
  const posRef = useRef(getInitialHomePos(config.offsetX));
  const rafRef = useRef<number>(0);
  const arrivedRef = useRef(false);

  useEffect(() => {
    arrivedRef.current = false;
  }, [targetPos]);

  // Reset position to be safely below the Topbar obstacle when coming out of the home
  useEffect(() => {
    if (visible && !targetPos && isFollowing) {
      const mount = document.getElementById("pet-home-mount");
      if (mount) {
        const rect = mount.getBoundingClientRect();
        posRef.current = {
          x: rect.left + rect.width / 2 - PET_SIZE.width / 2 + config.offsetX,
          y: rect.bottom + 12, // Safely below the Topbar bottom edge + padding
        };
      }
    }
  }, [visible, targetPos, isFollowing, config.offsetX]);

  const animate = useCallback(() => {
    const el = elRef.current;
    if (!el) {
      rafRef.current = requestAnimationFrame(animate);
      return;
    }

    const pos = posRef.current;
    const obstacles = getObstacleRects();

    if (isFollowing && mouseRef.current) {
      // ── Desired position based on cursor ──
      const desiredX = mouseRef.current.x + config.offsetX - PET_SIZE.width / 2;
      const desiredY = mouseRef.current.y + config.offsetY - PET_SIZE.height / 2;

      // Interpolate current position toward desired
      const nextX = pos.x + (desiredX - pos.x) * config.followSpeed;
      const nextY = pos.y + (desiredY - pos.y) * config.followSpeed;

      // If the interpolated position overlaps an obstacle, keep old position
      if (!overlapsAny(nextX, nextY, obstacles)) {
        pos.x = nextX;
        pos.y = nextY;
      } else {
        // Try sliding along X only
        if (!overlapsAny(nextX, pos.y, obstacles)) {
          pos.x = nextX;
        }
        // Try sliding along Y only
        else if (!overlapsAny(pos.x, nextY, obstacles)) {
          pos.y = nextY;
        }
        // Both axes blocked — use minimum-penetration resolution to push out
        else {
          const resolved = resolveCollisions(pos.x, pos.y, obstacles);
          pos.x = resolved.x;
          pos.y = resolved.y;
        }
      }
    } else if (targetPos && !arrivedRef.current) {
      // ── Moving toward home door (Bypass collision check so they can reach the house inside the topbar) ──
      const tx = targetPos.x - PET_SIZE.width / 2;
      const ty = targetPos.y - PET_SIZE.height / 2;
      const dx = tx - pos.x;
      const dy = ty - pos.y;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist < 4) {
        pos.x = tx;
        pos.y = ty;
        arrivedRef.current = true;
        onArrived?.();
      } else {
        // Slow down step multiplier from 0.12 to 0.04 for a slow, smooth entrance/exit effect
        pos.x += dx * 0.04;
        pos.y += dy * 0.04;
      }
    }

    // Viewport clamping
    pos.x = Math.max(0, Math.min(pos.x, window.innerWidth - PET_SIZE.width));
    pos.y = Math.max(0, Math.min(pos.y, window.innerHeight - PET_SIZE.height));

    el.style.transform = `translate3d(${Math.round(pos.x)}px, ${Math.round(pos.y)}px, 0)`;

    rafRef.current = requestAnimationFrame(animate);
  }, [isFollowing, mouseRef, config, targetPos, onArrived]);

  useEffect(() => {
    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [animate]);

  return (
    <div
      ref={elRef}
      className="orion-pet"
      style={{
        opacity: visible ? 1 : 0,
        visibility: visible ? "visible" : "hidden",
        pointerEvents: "none",
        top: 0,
        left: 0,
      }}
      aria-hidden={!visible}
    >
      <PetSvg config={config} />
    </div>
  );
});

export { PetCharacter };
