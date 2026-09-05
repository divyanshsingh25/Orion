import { useEffect, useState } from "react";
import { getCurrentUser, getCurrentUserStored, type UserProfile } from "@/services/api";

export function useCurrentUser() {
  const [user, setUser] = useState<UserProfile | null>(() => getCurrentUserStored());
  const [loading, setLoading] = useState<boolean>(!user);

  useEffect(() => {
    const handleUserUpdate = (event: Event) => {
      const customEvent = event as CustomEvent<UserProfile | null>;
      setUser(customEvent.detail ?? getCurrentUserStored());
    };

    window.addEventListener("orion.user_updated", handleUserUpdate);
    window.addEventListener("storage", handleUserUpdate);

    // If access token is present, fetch fresh user data
    const token = window.localStorage.getItem("orion.access_token");
    if (token) {
      getCurrentUser()
        .then((freshUser) => {
          setUser(freshUser);
        })
        .catch(() => {
          // Token may be invalid or network issue; keep stored if present
        })
        .finally(() => {
          setLoading(false);
        });
    } else {
      setLoading(false);
    }

    return () => {
      window.removeEventListener("orion.user_updated", handleUserUpdate);
      window.removeEventListener("storage", handleUserUpdate);
    };
  }, []);

  return { user, loading };
}
