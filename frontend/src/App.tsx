import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Analytics } from "@vercel/analytics/react";
import { AppLayout } from "@/layouts/AppLayout";
import { LandingPage } from "@/pages/LandingPage";
import { LoginPage } from "@/pages/LoginPage";
import { VerifyEmailPage } from "@/pages/VerifyEmailPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { NewScanPage } from "@/pages/NewScanPage";
import { LiveScanPage } from "@/pages/LiveScanPage";
import { ScanHistoryPage } from "@/pages/ScanHistoryPage";
import { VulnerabilitiesPage } from "@/pages/VulnerabilitiesPage";
import { AttackSurfacePage } from "@/pages/AttackSurfacePage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { SimplePage } from "@/pages/SimplePage";
import { useThemeStore } from "@/hooks/useThemeStore";

function ThemeBridge() {
  const isDark = useThemeStore((state) => state.isDark);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDark);
  }, [isDark]);

  return null;
}

function AppRoutes() {
  const location = useLocation();
  const accessToken = window.localStorage.getItem("orion.access_token");

  // Public Landing Page (first screen for anyone visiting Orion root)
  if (location.pathname === "/" || location.pathname === "/landing" || location.pathname === "/index.html") {
    return <LandingPage />;
  }

  if (location.pathname === "/login") {
    return <LoginPage />;
  }

  if (location.pathname === "/verify-email") {
    return <VerifyEmailPage />;
  }

  // Protected authenticated routes: if not logged in, direct visitors to the landing page first
  if (!accessToken) {
    return <Navigate to="/" replace />;
  }

  return (
    <AppLayout>
      <Routes>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/new-scan" element={<NewScanPage />} />
        <Route path="/live-scan" element={<LiveScanPage />} />
        <Route path="/scan-history" element={<ScanHistoryPage />} />
        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="/attack-surface" element={<AttackSurfacePage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/compare" element={<SimplePage title="Compare" subtitle="Compare scan posture across targets" />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}

export default function App() {
  return (
    <>
      <ThemeBridge />
      <AppRoutes />
      <Analytics />
    </>
  );
}