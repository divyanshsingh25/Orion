/**
 * Orion Hacker Pets — Configuration
 *
 * Constants, types, and per-pet config for the three hacker companions.
 */

export type PetState =
  | "FOLLOWING"
  | "ENTERING_HOME"
  | "INSIDE_HOME"
  | "LEAVING_HOME";

export interface PetConfig {
  id: string;
  name: string;
  /** Interpolation speed — lower = slower/laggier follow */
  followSpeed: number;
  /** Pixel offset from cursor so pets don't overlap */
  offsetX: number;
  offsetY: number;
  /** Delay (ms) before this pet starts entering/leaving the house */
  staggerDelay: number;
  /** Hat color */
  hatColor: string;
  /** Hat highlight / brim accent */
  hatAccent: string;
  /** Skin tone */
  skinColor: string;
  /** Body / shirt color */
  bodyColor: string;
  /** Eye style variant */
  eyeStyle: "playful" | "calm" | "friendly";
  /** Accessory type */
  accessory: "circuit" | "terminal" | "shield";
  /** Accent glow color (for cyberpunk effects) */
  glowColor: string;
  /** Blink interval randomization (ms) */
  blinkInterval: number;
  /** Bounce amplitude (px) */
  bounceAmp: number;
}

export const PET_CONFIGS: PetConfig[] = [
  {
    id: "red-hat",
    name: "Red Hat",
    followSpeed: 0.09,
    offsetX: -45,
    offsetY: 15,
    staggerDelay: 0,
    hatColor: "#ef4444",
    hatAccent: "#fca5a5",
    skinColor: "#fde68a",
    bodyColor: "#374151",
    eyeStyle: "playful",
    accessory: "circuit",
    glowColor: "rgba(239, 68, 68, 0.4)",
    blinkInterval: 3200,
    bounceAmp: 3,
  },
  {
    id: "black-hat",
    name: "Black Hat",
    followSpeed: 0.065,
    offsetX: 5,
    offsetY: 48,
    staggerDelay: 350,
    hatColor: "#1e1b4b",
    hatAccent: "#7c3aed",
    skinColor: "#fcd9b6",
    bodyColor: "#1f2937",
    eyeStyle: "calm",
    accessory: "terminal",
    glowColor: "rgba(124, 58, 237, 0.4)",
    blinkInterval: 4000,
    bounceAmp: 1.5,
  },
  {
    id: "white-hat",
    name: "White Hat",
    followSpeed: 0.05,
    offsetX: 45,
    offsetY: 30,
    staggerDelay: 700,
    hatColor: "#f1f5f9",
    hatAccent: "#06b6d4",
    skinColor: "#fde2c8",
    bodyColor: "#334155",
    eyeStyle: "friendly",
    accessory: "shield",
    glowColor: "rgba(6, 182, 212, 0.4)",
    blinkInterval: 3600,
    bounceAmp: 2,
  },
];

/** Pet sprite size */
export const PET_SIZE = { width: 28, height: 34 };

/** Duration for enter/leave sequences (ms) */
export const TRANSITION_DURATION = 700;

/** Duration for door open/close (ms) */
export const DOOR_DURATION = 350;
