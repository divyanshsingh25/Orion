import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { AppLayout } from "@/layouts/AppLayout";
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
  const isPublic = location.pathname === "/login" || location.pathname === "/verify-email";
  const accessToken = window.localStorage.getItem("orion.access_token");

  if (!isPublic && !accessToken) {
    return <Navigate to="/login" replace />;
  }

  if (location.pathname === "/verify-email") {
    return <VerifyEmailPage />;
  }

  if (location.pathname === "/login") {
    return <LoginPage />;
  }

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
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
    </>
  );
}