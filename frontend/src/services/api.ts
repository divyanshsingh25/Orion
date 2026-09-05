import axios, { type AxiosError, type InternalAxiosRequestConfig } from "axios";
import { usePetStore } from "@/components/pets/usePetStore";
import type {
  AssistantMessage,
  AttackSurfaceAsset,
  ChartDatum,
  LiveModule,
  Metric,
  ReportItem,
  Risk,
  ScanHistoryRow,
  TerminalEvent,
  Vulnerability,
} from "@/types/dashboard";

const viteEnv = (import.meta as { env?: Record<string, string | undefined> }).env;
const baseURL = viteEnv?.VITE_API_BASE_URL ?? "http://localhost:8123/api/v1";
const apiBase = new URL(baseURL);
const wsBase = `${apiBase.protocol === "https:" ? "wss:" : "ws:"}//${apiBase.host}${apiBase.pathname.replace(/\/$/, "")}`;

const storageKeys = {
  accessToken: "orion.access_token",
  refreshToken: "orion.refresh_token",
  currentUser: "orion.current_user",
};

export interface UserProfile {
  id: string;
  email: string;
  username: string;
  full_name?: string | null;
  organization?: string | null;
  role?: string;
  auth_provider: string;
  avatar_url?: string | null;
  is_active: boolean;
  is_verified: boolean;
  created_at?: string;
}

export interface DashboardData {
  metrics: Metric[];
  severity: ChartDatum[];
  activity: Array<{ day: string; Critical: number; High: number; Medium: number }>;
  coverage: Array<{ domain: string; score: number }>;
  status: ChartDatum[];
  attackVectors: ChartDatum[];
  cvss: Array<{ range: string; value: number; color: string }>;
  risks: Risk[];
  scanHistory: ScanHistoryRow[];
  terminalEvents: TerminalEvent[];
  liveModules: LiveModule[];
  assistantMessages: AssistantMessage[];
  vulnerabilities: Vulnerability[];
  attackSurfaceAssets: AttackSurfaceAsset[];
  reports: ReportItem[];
  scanSummary: Record<string, unknown>;
  securityScore: number;
}

export interface LaunchAssessmentPayload {
  targetUrl: string;
  projectName?: string;
  scanType?: string;
  depth?: string;
  authConfig?: Record<string, unknown> | null;
}

const api = axios.create({
  baseURL,
  timeout: 30000,
});

function getAccessToken() {
  return window.localStorage.getItem(storageKeys.accessToken);
}

function getRefreshToken() {
  return window.localStorage.getItem(storageKeys.refreshToken);
}

export function setAuthTokens(accessToken: string, refreshToken: string) {
  window.localStorage.setItem(storageKeys.accessToken, accessToken);
  window.localStorage.setItem(storageKeys.refreshToken, refreshToken);
}

export function setCurrentUser(user: UserProfile) {
  window.localStorage.setItem(storageKeys.currentUser, JSON.stringify(user));
  window.dispatchEvent(new CustomEvent("orion.user_updated", { detail: user }));
}

export function getCurrentUserStored(): UserProfile | null {
  try {
    const raw = window.localStorage.getItem(storageKeys.currentUser);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function clearAuthTokens() {
  window.localStorage.removeItem(storageKeys.accessToken);
  window.localStorage.removeItem(storageKeys.refreshToken);
  window.localStorage.removeItem(storageKeys.currentUser);
  usePetStore.getState().reset();
  window.dispatchEvent(new CustomEvent("orion.user_updated", { detail: null }));
}

async function refreshAuthToken(): Promise<string | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return null;
  }

  const response = await axios.post(`${baseURL}/auth/refresh`, { refresh_token: refreshToken });
  setAuthTokens(response.data.access_token, response.data.refresh_token);
  return response.data.access_token as string;
}

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;

    // Strict email verification enforcement: clear any existing session if unverified
    const errorData = error.response?.data as { code?: string; detail?: string } | undefined;
    if (error.response?.status === 403 && errorData?.code === "EMAIL_NOT_VERIFIED") {
      clearAuthTokens();
      return Promise.reject(error);
    }

    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      originalRequest._retry = true;
      const newToken = await refreshAuthToken().catch(() => null);
      if (newToken) {
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api.request(originalRequest);
      }
      clearAuthTokens();
    }
    return Promise.reject(error);
  },
);

export async function login(identifier: string, password: string) {
  const { data } = await api.post("/auth/login", { identifier, password });
  setAuthTokens(data.tokens.access_token, data.tokens.refresh_token);
  if (data.user) {
    setCurrentUser(data.user);
  }
  return data;
}

export async function getCurrentUser(): Promise<UserProfile> {
  const { data } = await api.get("/auth/me");
  setCurrentUser(data);
  return data;
}

export async function updateProfile(payload: { full_name?: string; username?: string; organization?: string }): Promise<UserProfile> {
  const { data } = await api.put("/auth/me", payload);
  setCurrentUser(data);
  return data;
}

export async function register(email: string, password: string, username: string, fullName: string, organization: string) {
  const { data } = await api.post("/auth/register", {
    email,
    password,
    username,
    full_name: fullName,
    organization,
  });
  return data;
}

export async function verifyEmail(token: string, email?: string) {
  const { data } = await api.post("/auth/verify-email", {
    token: token.trim(),
    email: email?.trim() || undefined,
  });
  return data;
}

export async function resendVerification(email: string) {
  const { data } = await api.post("/auth/resend-verification", { email: email.trim() });
  return data;
}

export async function getDashboardData(): Promise<DashboardData> {
  const { data } = await api.get("/dashboard/summary");

  const scanHistory = (data.scanHistory ?? []) as ScanHistoryRow[];
  const activityMap = new Map<string, { Critical: number; High: number; Medium: number }>();
  scanHistory.forEach((row) => {
    const day = new Date(row.started).toLocaleDateString("en-US", { weekday: "short" });
    const current = activityMap.get(day) ?? { Critical: 0, High: 0, Medium: 0 };
    current.Critical += row.critical;
    current.High += row.high;
    current.Medium += row.medium;
    activityMap.set(day, current);
  });

  const activity = Array.from(activityMap.entries()).map(([day, counts]) => ({ day, ...counts }));

  return {
    metrics: data.metrics ?? [],
    severity: data.severity ?? [],
    activity: activity.length > 0
      ? activity
      : [
          { day: "Mon", Critical: 0, High: 0, Medium: 0 },
          { day: "Tue", Critical: 0, High: 0, Medium: 0 },
          { day: "Wed", Critical: 0, High: 0, Medium: 0 },
          { day: "Thu", Critical: 0, High: 0, Medium: 0 },
          { day: "Fri", Critical: 0, High: 0, Medium: 0 },
          { day: "Sat", Critical: 0, High: 0, Medium: 0 },
          { day: "Sun", Critical: 0, High: 0, Medium: 0 },
        ],
    coverage: (data.coverage ?? []).map((item: { name?: string; domain?: string; value?: number; score?: number }) => ({
      domain: item.domain ?? item.name ?? "Unknown",
      score: item.score ?? item.value ?? 0,
    })),
    status: data.status ?? [],
    attackVectors: data.attackVectors ?? [],
    cvss: (data.cvss ?? []).map((item: { name?: string; range?: string; value: number; color: string }) => ({
      range: item.range ?? item.name ?? "Unknown",
      value: item.value,
      color: item.color,
    })),
    risks: data.risks ?? [],
    scanHistory,
    terminalEvents: data.terminalEvents ?? [],
    liveModules: data.liveModules ?? [],
    assistantMessages: data.assistantMessages ?? [],
    vulnerabilities: (data.vulnerabilities ?? []).map((item: any) => ({
      ...item,
      asset: item.affected_url || item.affected_parameter || item.target_id || "Global",
      owasp: item.owasp_category || "None",
      cwe: item.cwe_id || "None",
      cvss: parseFloat(item.cvss_score || "0"),
    })),
    attackSurfaceAssets: data.attackSurfaceAssets ?? [],
    reports: data.reports ?? [],
    scanSummary: data.scanSummary ?? {},
    securityScore: data.securityScore ?? 100,
  };
}

export async function listProjects() {
  const { data } = await api.get("/projects");
  return data as Array<{ id: string; name: string; description?: string | null }>;
}

export async function createProject(name: string, description?: string | null) {
  const { data } = await api.post("/projects", { name, description });
  return data as { id: string; name: string; description?: string | null };
}

export async function listTargets(projectId?: string) {
  const { data } = await api.get("/targets", { params: projectId ? { project_id: projectId } : undefined });
  return data as Array<{ id: string; project_id: string; url: string; host: string; scheme: string; risk_score: number }>;
}

export async function createTarget(projectId: string, url: string) {
  const { data } = await api.post("/targets", { project_id: projectId, url });
  return data as { id: string; project_id: string; url: string; host: string; scheme: string; risk_score: number };
}

export interface ScanDetail {
  id: string;
  project_id?: string;
  target_id?: string;
  user_id?: string;
  scan_type?: string;
  depth?: string;
  status: string;
  progress_percent: number;
  current_module?: string | null;
  current_url?: string | null;
  target_url?: string | null;
  total_findings: number;
  requests_count?: number;
  endpoints_count?: number;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  error_message?: string | null;
  live_events?: TerminalEvent[];
  live_modules?: LiveModule[];
  eta_seconds?: number;
  report_id?: string | null;
}

export async function createScan(targetId: string, scanType = "full", depth = "medium", authConfig: Record<string, unknown> | null = null) {
  const { data } = await api.post("/scans", {
    target_id: targetId,
    scan_type: scanType,
    depth,
    auth_config: authConfig,
  });
  return data as { id: string; target_id: string; scan_type: string; status: string; progress_percent: number };
}

export async function getActiveScan(): Promise<ScanDetail | null> {
  try {
    const { data } = await api.get("/scans/active");
    return (data as ScanDetail) ?? null;
  } catch {
    return null;
  }
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const { data } = await api.get(`/scans/${scanId}`);
  return data as ScanDetail;
}

export async function cancelScan(scanId: string) {
  const { data } = await api.post(`/scans/${scanId}/cancel`);
  return data as ScanDetail;
}

export async function launchAssessment(payload: LaunchAssessmentPayload) {
  const targetUrl = new URL(payload.targetUrl);
  const projectName = payload.projectName ?? (targetUrl.hostname.replace(/^www\./, "") || targetUrl.hostname);
  const projects = await listProjects();
  let project = projects.find((item) => item.name.toLowerCase() === projectName.toLowerCase());

  if (!project) {
    project = await createProject(projectName, `Automated assessment for ${targetUrl.hostname}`);
  }

  const targets = await listTargets(project.id);
  let target = targets.find((item) => item.url === payload.targetUrl);
  if (!target) {
    target = await createTarget(project.id, payload.targetUrl);
  }

  const scan = await createScan(
    target.id,
    payload.scanType ?? "full",
    payload.depth ?? "medium",
    payload.authConfig ?? null,
  );

  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem("orion.active_scan_id", scan.id);
    window.localStorage.setItem("orion.active_target", payload.targetUrl);
  }

  return { project, target, scan };
}

export async function getReports() {
  const { data } = await api.get("/reports");
  return data as ReportItem[];
}

export async function deleteReport(reportId: string) {
  await api.delete(`/reports/${reportId}`);
}

export async function generateReport(scanId: string, format: string) {
  const { data } = await api.post(`/reports/generate/${scanId}?format=${format}`);
  return data;
}

export async function downloadReport(reportId: string, filename?: string) {
  const response = await api.get(`/reports/${reportId}/download`, { responseType: "blob" });
  const contentType = typeof response.headers["content-type"] === "string" ? response.headers["content-type"] : "application/octet-stream";
  const blob = new Blob([response.data], { type: contentType });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename ?? `orion-report-${reportId}`;
  anchor.click();
  window.URL.revokeObjectURL(url);
}

export async function getFindings(scanId?: string) {
  const url = scanId ? `/findings?scan_id=${scanId}&page_size=100` : "/findings?page_size=100";
  const { data } = await api.get(url);
  
  const rawItems = data.items || data || [];
  const items = rawItems.map((item: any) => ({
    ...item,
    asset: item.affected_url || item.affected_parameter || item.target_id || "Global",
    owasp: item.owasp_category || "None",
    cwe: item.cwe_id || "None",
    cvss: parseFloat(item.cvss_score || "0"),
  }));

  return { items } as { items: Vulnerability[] };
}

export async function logout() {
  clearAuthTokens();
}

export function getScanWebSocketUrl(scanId: string, token: string) {
  return `${wsBase}/scans/ws/${scanId}?token=${encodeURIComponent(token)}`;
}

export async function sendChatMessage(messages: AssistantMessage[]) {
  const { data } = await api.post("/chat", { messages });
  return data as AssistantMessage;
}
