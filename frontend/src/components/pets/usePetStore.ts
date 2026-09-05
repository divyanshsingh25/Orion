/**
 * Orion Hacker Pets — Zustand State Store
 *
 * Simple state machine with guarded transitions to prevent
 * duplicate clicks during animations.
 */

import { create } from "zustand";
import type { PetState } from "./petConfig";

interface PetStore {
  state: PetState;
  setState: (next: PetState) => void;
  reset: () => void;
}

const VALID_TRANSITIONS: Record<PetState, PetState[]> = {
  FOLLOWING: ["ENTERING_HOME"],
  ENTERING_HOME: ["INSIDE_HOME"],
  INSIDE_HOME: ["LEAVING_HOME"],
  LEAVING_HOME: ["FOLLOWING"],
};

export const usePetStore = create<PetStore>((set, get) => ({
  state: "INSIDE_HOME",
  setState: (next) => {
    const current = get().state;
    if (VALID_TRANSITIONS[current]?.includes(next)) {
      set({ state: next });
    }
  },
  reset: () => set({ state: "INSIDE_HOME" }),
}));
