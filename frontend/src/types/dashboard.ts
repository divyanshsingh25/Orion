export type SeverityName = "Critical" | "High" | "Medium" | "Low";

export interface Metric {
  label: string;
  value: number;
  delta: string;
  trend: "up" | "down";
  accent: "cyan" | "red" | "orange" | "yellow" | "purple";
}

export interface ChartDatum {
  name: string;
  value: number;
  color: string;
}

export interface Risk {
  title: string;
  severity: Exclude<SeverityName, "Low">;
}

export interface ScanHistoryRow {
  id?: string;
  target: string;
  status: "Running" | "Completed" | "Failed" | "Cancelled";
  type: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  started: string;
  duration: string;
}

export interface TerminalEvent {
  time: string;
  level: "INFO" | "SCAN" | "FOUND" | "WARN";
  message: string;
}

export interface LiveModule {
  name: string;
  status: "Complete" | "Scanning" | "Queued" | "Cancelled";
  progress: number;
  findings: number;
}

export interface AssistantMessage {
  role: "assistant" | "user" | "system";
  content: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  asset: string;
  owasp: string;
  cwe: string;
  cvss: number;
  severity: SeverityName;
  status: "Open" | "In Review" | "Accepted";
  evidence: string;
  remediation: string;
}

export interface AttackSurfaceAsset {
  name: string;
  type: string;
  risk: SeverityName;
  ports: number[];
  endpoints: number;
  technologies: string[];
  certificate: string;
  certificate_subject?: string;
  certificate_issuer?: string;
  certificate_expiry?: string;
  subdomains: string[];
  exposure: number;
}

export interface ReportItem {
  id?: string;
  scan_id?: string;
  name: string;
  type: "PDF" | "HTML";
  audience: string;
  updated: string;
  pages: number;
  status: "Ready" | "Draft";
  score: number;
}