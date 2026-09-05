/**
 * Orion Hacker Pets — Orchestrator
 *
 * Top-level component that wires together PetHome + 3 PetCharacters.
 * Handles mouse tracking via refs (zero React re-renders per frame),
 * and manages the enter/leave sequences with staggered timing.
 */

import { useRef, useEffect, useState, useCallback } from "react";
import { PetCharacter } from "./PetCharacter";
import { PetHome } from "./PetHome";
import { usePetStore } from "./usePetStore";
import {
  PET_CONFIGS,
  TRANSITION_DURATION,
  DOOR_DURATION,
} from "./petConfig";
import "./pets.css";

/** Calculate home door position from the topbar mount element */
function getHomeDoorPos() {
  const mount = document.getElementById("pet-home-mount");
  if (mount) {
    const rect = mount.getBoundingClientRect();
    return {
      x: rect.left + rect.width / 2,
      y: rect.top + rect.height / 2,
    };
  }
  return { x: window.innerWidth - 80, y: 160 };
}

export function OrionPets() {
  const mouseRef = useRef<{ x: number; y: number }>({
    x: window.innerWidth / 2,
    y: window.innerHeight / 2,
  });

  const petState = usePetStore((s) => s.state);
  const setPetState = usePetStore((s) => s.setState);

  const [doorOpen, setDoorOpen] = useState(false);
  const [petVisibility, setPetVisibility] = useState<boolean[]>(() => [
    petState === "FOLLOWING",
    petState === "FOLLOWING",
    petState === "FOLLOWING",
  ]);
  const [targetPositions, setTargetPositions] = useState<
    ({ x: number; y: number } | null)[]
  >([null, null, null]);

  const arrivedCountRef = useRef(0);

  // Reduced motion detection
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handler = (e: MediaQueryListEvent) => {
      // CSS handles the visual changes via the media query
      void e;
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Mouse tracking — ref only, no state updates
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY };
    };
    document.addEventListener("mousemove", handleMouseMove, { passive: true });
    return () => document.removeEventListener("mousemove", handleMouseMove);
  }, []);

  // House click handler
  const handleHomeClick = useCallback(() => {
    if (petState === "FOLLOWING") {
      setPetState("ENTERING_HOME");
      arrivedCountRef.current = 0;
      setDoorOpen(true);

      const homePos = getHomeDoorPos();

      // Stagger each pet moving toward home
      PET_CONFIGS.forEach((cfg, i) => {
        setTimeout(() => {
          setTargetPositions((prev) => {
            const next = [...prev];
            next[i] = { x: homePos.x, y: homePos.y };
            return next;
          });
        }, cfg.staggerDelay);
      });
    } else if (petState === "INSIDE_HOME") {
      setPetState("LEAVING_HOME");
      arrivedCountRef.current = 0;
      setDoorOpen(true);

      const homePos = getHomeDoorPos();

      // Stagger each pet appearing and immediately following the cursor
      PET_CONFIGS.forEach((cfg, i) => {
        setTimeout(() => {
          setPetVisibility((prev) => {
            const next = [...prev];
            next[i] = true;
            return next;
          });
          setTargetPositions((prev) => {
            const next = [...prev];
            next[i] = null; // Start following immediately
            return next;
          });

          if (i === PET_CONFIGS.length - 1) {
            setTimeout(() => {
              setDoorOpen(false);
              setPetState("FOLLOWING");
            }, TRANSITION_DURATION);
          }
        }, DOOR_DURATION + cfg.staggerDelay);
      });
    }
  }, [petState, setPetState]);

  // Pet arrived at home callback
  const handlePetArrived = useCallback(
    (index: number) => {
      if (petState === "ENTERING_HOME") {
        setPetVisibility((prev) => {
          const next = [...prev];
          next[index] = false;
          return next;
        });

        arrivedCountRef.current += 1;

        if (arrivedCountRef.current >= PET_CONFIGS.length) {
          setTimeout(() => {
            setDoorOpen(false);
            setTargetPositions([null, null, null]);
            setPetState("INSIDE_HOME");
          }, DOOR_DURATION);
        }
      } else if (petState === "LEAVING_HOME") {
        // Clear target so they start following cursor
        setTargetPositions((prev) => {
          const next = [...prev];
          next[index] = null;
          return next;
        });

        arrivedCountRef.current += 1;

        if (arrivedCountRef.current >= PET_CONFIGS.length) {
          setTimeout(() => {
            setDoorOpen(false);
            setPetState("FOLLOWING");
          }, DOOR_DURATION);
        }
      }
    },
    [petState, setPetState]
  );

  const isFollowing = petState === "FOLLOWING" || petState === "LEAVING_HOME";

  return (
    <>
      {PET_CONFIGS.map((cfg, i) => (
        <PetCharacter
          key={cfg.id}
          config={cfg}
          mouseRef={mouseRef}
          isFollowing={isFollowing && targetPositions[i] === null}
          targetPos={targetPositions[i]}
          onArrived={() => handlePetArrived(i)}
          visible={petVisibility[i]}
        />
      ))}

      <PetHome
        onClick={handleHomeClick}
        doorOpen={doorOpen}
        petsInside={petState === "INSIDE_HOME"}
      />
    </>
  );
}
