import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import {
  Shield,
  ShieldCheck,
  Scan,
  Activity,
  Zap,
  Terminal,
  Server,
  Lock,
  FileText,
  Cpu,
  Globe2,
  Code2,
  CheckCircle2,
  ArrowRight,
  ArrowUpRight,
  ExternalLink,
  ChevronRight,
  Layers,
  Sparkles,
  Search,
  Eye,
  AlertTriangle,
  Play,
  RotateCcw,
  Check,
  ChevronDown,
  Database,
  Radio,
  Sliders,
  Award,
  RefreshCw,
  Clock,
  Bug,
  Flame,
  CheckCircle,
  Network,
  Menu,
  X
} from "lucide-react";
import { motion, useScroll, useSpring, AnimatePresence, useReducedMotion } from "framer-motion";
import { Button } from "@/components/ui/button";

// Abstract Security Assessment Pipeline Visualization Nodes
const PIPELINE_NODES = [
  {
    id: "target",
    phase: "TARGET",
    label: "TARGET DISCOVERED",
    value: "api.enterprise-corp.io",
    detail: "Scope Verified • 63 Ports • TLS 1.3",
    status: "SCOPED",
    badgeColor: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
    dotColor: "bg-cyan-400",
    icon: Globe2,
    telemetry: {
      ip: "104.21.58.192",
      dns: "A, AAAA, MX Verified",
      ports: "80, 443, 8080 Active"
    }
  },
  {
    id: "discovery",
    phase: "DISCOVERY",
    label: "ENDPOINTS ANALYZED",
    value: "84 Routes • 14 Subdomains",
    detail: "Headless Chromium SPA Crawl",
    status: "MAPPED",
    badgeColor: "bg-sky-500/10 text-sky-300 border-sky-500/30",
    dotColor: "bg-sky-400",
    icon: Search,
    telemetry: {
      spa: "DOM Interception Active",
      forms: "18 Input Vectors Indexed",
      tree: "API OpenAPI / GraphQL Mapped"
    }
  },
  {
    id: "analysis",
    phase: "ANALYSIS",
    label: "SECURITY PROBES ACTIVE",
    value: "15 OWASP Engines Parallel",
    detail: "Differential Injection & Header Posture",
    status: "ANALYZING",
    badgeColor: "bg-blue-500/10 text-blue-300 border-blue-500/30",
    dotColor: "bg-blue-400",
    icon: Cpu,
    telemetry: {
      engines: "SQLi, XSS, SSRF, RCE, IDOR",
      tls: "Ciphers Enforced (>=128-bit)",
      policy: "CSP, HSTS, CORS Audited"
    }
  },
  {
    id: "detection",
    phase: "VULNERABILITY DETECTION",
    label: "VULNERABILITIES DETECTED",
    value: "2 Flaws Confirmed via Replay",
    detail: "Time-Blind SQLi • Permissive CORS",
    status: "CONFIRMED",
    badgeColor: "bg-rose-500/10 text-rose-300 border-rose-500/30",
    dotColor: "bg-rose-400",
    icon: AlertTriangle,
    telemetry: {
      sqli: "CWE-89 • CVSS 9.8 Critical",
      cors: "CWE-942 • High Origin Leak",
      evidence: "Automated HTTP Replay 5.02s"
    }
  },
  {
    id: "risk",
    phase: "RISK ASSESSMENT",
    label: "RISK ASSESSMENT COMPLETE",
    value: "CVSS 9.8 Critical • Score 42/100",
    detail: "Root-Cause SHA256 • PDF Compiled",
    status: "COMPLETE",
    badgeColor: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
    dotColor: "bg-emerald-400",
    icon: ShieldCheck,
    telemetry: {
      scorecard: "Enterprise Grade A-F",
      dedup: "Zero False Duplicate Keys",
      export: "Executive PDF Ready"
    }
  }
];

// Capabilities Strip List
const CAPABILITY_STRIP = [
  { label: "Automated Discovery", icon: Search },
  { label: "Vulnerability Detection", icon: Zap },
  { label: "OWASP Mapping", icon: Layers },
  { label: "CWE Classification", icon: Code2 },
  { label: "CVSS Risk Scoring", icon: Activity },
  { label: "Evidence & Remediation", icon: CheckCircle2 },
  { label: "Professional PDF Reports", icon: FileText },
];

export function LandingPage() {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeVisualNode, setActiveVisualNode] = useState(0);
  const [terminalLogIndex, setTerminalLogIndex] = useState(0);
  const [isPlayingLogs, setIsPlayingLogs] = useState(true);
  const [targetInput, setTargetInput] = useState("https://api.your-company.com");
  const [simulatedScanRunning, setSimulatedScanRunning] = useState(false);
  const [simulatedProgress, setSimulatedProgress] = useState(0);
  const [activeFaq, setActiveFaq] = useState<number | null>(null);

  // Scroll Progress Animation
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 100, damping: 30, restDelta: 0.001 });

  useEffect(() => {
    const token = window.localStorage.getItem("orion.access_token");
    setIsAuthenticated(Boolean(token));
  }, []);

  // Cycle through the pipeline nodes automatically every 3.5s for dynamic visualization
  useEffect(() => {
    const timer = setInterval(() => {
      setActiveVisualNode((prev) => (prev + 1) % PIPELINE_NODES.length);
    }, 3500);
    return () => clearInterval(timer);
  }, []);

  // Simulated Terminal Log Stream for Interactive Demo
  const terminalLogs = [
    { time: "00:01", lvl: "SCAN", msg: "Target verified: https://api.your-company.com (IP: 104.21.58.192)" },
    { time: "00:03", lvl: "DNS", msg: "Resolved A, AAAA, MX, NS records; 14 subdomains identified via dictionary" },
    { time: "00:05", lvl: "PORT", msg: "TCP Connect probe: Port 80, 443, 5432, 8080 OPEN — Services fingerprinted" },
    { time: "00:08", lvl: "TLS", msg: "TLS 1.3 enforced. Ciphers verified. Certificate valid for 248 days" },
    { time: "00:11", lvl: "CRAWL", msg: "SPA Crawler indexed 84 endpoints, 18 input forms, 3 API routers" },
    { time: "00:14", lvl: "PROBE", msg: "Testing 15 OWASP injection engines (SQLi, XSS, SSRF, RCE, IDOR, XXE)..." },
    { time: "00:17", lvl: "FOUND", msg: "High Severity: CORS reflects arbitrary Origin with credentials allowed" },
    { time: "00:20", lvl: "FOUND", msg: "Critical Severity: Time-blind SQL injection verified on /api/v1/orders" },
    { time: "00:22", lvl: "AI-REPLAY", msg: "Automated HTTP replay confirmed SQLi vulnerability (5.02s delay match)" },
    { time: "00:24", lvl: "REPORT", msg: "Generated Root-Cause SHA256 keys, CVSS v3.1 score: 9.8, PDF ready" }
  ];

  useEffect(() => {
    if (!isPlayingLogs) return;
    const timer = setInterval(() => {
      setTerminalLogIndex((prev) => (prev + 1) % terminalLogs.length);
    }, 2400);
    return () => clearInterval(timer);
  }, [isPlayingLogs, terminalLogs.length]);

  const handleRunSimulatedScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    setSimulatedScanRunning(true);
    setSimulatedProgress(10);
    const interval = setInterval(() => {
      setSimulatedProgress((p) => {
        if (p >= 100) {
          clearInterval(interval);
          setTimeout(() => setSimulatedScanRunning(false), 800);
          return 100;
        }
        return p + 15;
      });
    }, 280);
  };

  const handleAction = (mode: "login" | "signup" = "signup") => {
    if (isAuthenticated) {
      navigate("/dashboard");
    } else {
      navigate(`/login?mode=${mode}`);
    }
  };

  // Shared Animation Variants per user specification
  const sharedFadeUp = {
    hidden: {
      opacity: 0,
      y: shouldReduceMotion ? 0 : 24,
    },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.6,
        ease: [0.22, 1, 0.36, 1] as const,
      },
    },
  };

  const staggerContainer = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.05,
      },
    },
  };

  return (
    <div className="min-h-screen bg-[#07111F] text-[#F8FAFC] font-sans antialiased overflow-x-hidden selection:bg-[#06B6D4] selection:text-black">
      {/* 1. TOP SCROLL PROGRESS BAR */}
      <motion.div
        className="fixed top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-[#2563EB] via-sky-400 to-[#06B6D4] origin-left z-[100] shadow-[0_0_14px_rgba(6,182,212,0.8)]"
        style={{ scaleX }}
      />

      {/* ========================================================================= */}
      {/* FULL-VIEWPORT DARK CYBERSECURITY BACKGROUND */}
      {/* ========================================================================= */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        {/* Soft Radial Gradients */}
        <div className="absolute top-[-8%] left-[20%] w-[60vw] h-[55vw] rounded-full bg-[radial-gradient(circle,rgba(37,99,235,0.14),transparent_65%)] blur-[100px]" />
        <div className="absolute top-[25%] right-[-10%] w-[50vw] h-[50vw] rounded-full bg-[radial-gradient(circle,rgba(6,182,212,0.11),transparent_60%)] blur-[110px]" />
        <div className="absolute bottom-[5%] left-[-5%] w-[45vw] h-[45vw] rounded-full bg-[radial-gradient(circle,rgba(37,99,235,0.08),transparent_65%)] blur-[95px]" />

        {/* Subtle Technical Grid (48px square) */}
        <div
          className="absolute inset-0 opacity-[0.038]"
          style={{
            backgroundImage: `linear-gradient(to right, rgba(255,255,255,0.12) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.12) 1px, transparent 1px)`,
            backgroundSize: "48px 48px",
          }}
        />

        {/* Connected Node / Network Pattern Overlay */}
        <svg
          className="absolute inset-0 w-full h-full opacity-[0.16] stroke-slate-500"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#06B6D4" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#06B6D4" stopOpacity="0" />
            </radialGradient>
          </defs>
          <g strokeWidth="0.8" strokeDasharray="3 3">
            <line x1="12%" y1="18%" x2="28%" y2="28%" />
            <line x1="28%" y1="28%" x2="45%" y2="20%" />
            <line x1="45%" y1="20%" x2="62%" y2="32%" />
            <line x1="62%" y1="32%" x2="80%" y2="22%" />
            <line x1="80%" y1="22%" x2="92%" y2="35%" />
            <line x1="28%" y1="28%" x2="35%" y2="48%" />
            <line x1="62%" y1="32%" x2="70%" y2="52%" />
          </g>
          {/* Subtle node anchors */}
          <circle cx="12%" cy="18%" r="3" fill="#2563EB" opacity="0.6" />
          <circle cx="28%" cy="28%" r="3.5" fill="#06B6D4" opacity="0.8" />
          <circle cx="45%" cy="20%" r="2.5" fill="#2563EB" opacity="0.5" />
          <circle cx="62%" cy="32%" r="4" fill="#06B6D4" opacity="0.8" />
          <circle cx="80%" cy="22%" r="3" fill="#2563EB" opacity="0.6" />
          <circle cx="92%" cy="35%" r="3" fill="#06B6D4" opacity="0.7" />
          <circle cx="35%" cy="48%" r="2.5" fill="#2563EB" opacity="0.5" />
          <circle cx="70%" cy="52%" r="3" fill="#06B6D4" opacity="0.6" />
        </svg>

        {/* Subtle Animated Scanning Beam traversing the grid */}
        {!shouldReduceMotion && (
          <motion.div
            className="absolute left-0 right-0 h-[1.5px] bg-gradient-to-r from-transparent via-cyan-400/20 to-transparent pointer-events-none"
            initial={{ y: "0vh" }}
            animate={{ y: "100vh" }}
            transition={{
              duration: 12,
              repeat: Infinity,
              ease: "linear",
            }}
          />
        )}
      </div>

      {/* ========================================================================= */}
      {/* NAVBAR */}
      {/* ========================================================================= */}
      <header className="sticky top-0 z-50 w-full border-b border-white/[0.08] bg-[#07111F]/85 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
          {/* Left: ORION Logo + ORION */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-[#2563EB]/25 to-[#06B6D4]/25 border border-cyan-500/30 shadow-[0_0_18px_rgba(6,182,212,0.22)] overflow-hidden transition-transform duration-300 group-hover:scale-105">
              <img src="/orion-logo.png" alt="ORION Logo" className="h-full w-full object-cover scale-110" />
              <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border border-[#07111F] bg-emerald-400" />
            </div>
            <div>
              <div className="text-xl font-black tracking-tight text-white">
                ORION
              </div>
              <div className="text-[9.5px] font-semibold uppercase tracking-widest text-[#94A3B8]">
                Security Intelligence
              </div>
            </div>
          </Link>

          {/* Center: Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-8 text-[13.5px] font-medium text-[#94A3B8]">
            <a href="#platform" className="hover:text-white transition-colors">
              Platform
            </a>
            <a href="#features" className="hover:text-white transition-colors">
              Features
            </a>
            <a href="#how-it-works" className="hover:text-white transition-colors">
              How It Works
            </a>
            <a href="#reports" className="hover:text-white transition-colors">
              Reports
            </a>
            <a href="#about" className="hover:text-white transition-colors">
              About
            </a>
          </nav>

          {/* Right: Actions (Sign In + Get Started) */}
          <div className="hidden sm:flex items-center gap-2.5">
            {isAuthenticated ? (
              <Button
                onClick={() => navigate("/dashboard")}
                className="h-10 px-6 rounded-full bg-gradient-to-r from-[#2563EB] to-[#06B6D4] hover:from-[#1d4ed8] hover:to-[#0891b2] text-white font-semibold text-[13px] shadow-[0_0_24px_rgba(6,182,212,0.32)] transition-all flex items-center gap-2 border border-cyan-400/30"
              >
                Open Dashboard
                <ArrowRight className="h-4 w-4" />
              </Button>
            ) : (
              <>
                <Button
                  variant="ghost"
                  onClick={() => handleAction("login")}
                  className="h-10 px-4 rounded-full text-slate-300 hover:text-white hover:bg-white/[0.08] text-[13px] font-semibold transition-colors"
                >
                  Sign In
                </Button>
                <Button
                  onClick={() => handleAction("signup")}
                  className="h-10 px-5 rounded-full bg-gradient-to-r from-[#2563EB] to-[#06B6D4] hover:from-[#1d4ed8] hover:to-[#0891b2] text-white font-semibold text-[13px] shadow-[0_0_24px_rgba(6,182,212,0.32)] transition-all flex items-center gap-2 border border-cyan-400/30"
                >
                  Get Started
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </>
            )}
          </div>

          {/* Mobile Menu Toggle Button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-white/5 transition-colors"
              aria-label="Toggle Navigation Menu"
            >
              {isMobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        <AnimatePresence>
          {isMobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] as const }}
              className="md:hidden border-b border-white/10 bg-[#07111F]/95 backdrop-blur-2xl px-6 py-6 space-y-4"
            >
              <div className="flex flex-col space-y-3 text-sm font-medium text-slate-300">
                <a
                  href="#platform"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="py-1 hover:text-white transition-colors"
                >
                  Platform
                </a>
                <a
                  href="#features"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="py-1 hover:text-white transition-colors"
                >
                  Features
                </a>
                <a
                  href="#how-it-works"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="py-1 hover:text-white transition-colors"
                >
                  How It Works
                </a>
                <a
                  href="#reports"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="py-1 hover:text-white transition-colors"
                >
                  Reports
                </a>
                <a
                  href="#about"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="py-1 hover:text-white transition-colors"
                >
                  About
                </a>
              </div>

              <div className="pt-4 border-t border-white/10 flex flex-col gap-3">
                {isAuthenticated ? (
                  <Button
                    onClick={() => {
                      setIsMobileMenuOpen(false);
                      navigate("/dashboard");
                    }}
                    className="w-full h-11 rounded-full bg-gradient-to-r from-[#2563EB] to-[#06B6D4] text-white font-semibold text-xs shadow-[0_0_20px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2"
                  >
                    Open Dashboard
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                ) : (
                  <>
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setIsMobileMenuOpen(false);
                        handleAction("login");
                      }}
                      className="w-full h-10 rounded-full border border-white/10 bg-white/5 text-white font-semibold text-xs hover:bg-white/10"
                    >
                      Sign In
                    </Button>
                    <Button
                      onClick={() => {
                        setIsMobileMenuOpen(false);
                        handleAction("signup");
                      }}
                      className="w-full h-11 rounded-full bg-gradient-to-r from-[#2563EB] to-[#06B6D4] text-white font-semibold text-xs shadow-[0_0_20px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2"
                    >
                      Get Started Free
                      <ArrowRight className="h-4 w-4" />
                    </Button>
                  </>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </header>

      {/* ========================================================================= */}
      {/* 2. HERO SECTION */}
      {/* ========================================================================= */}
      <section className="relative z-10 pt-16 pb-20 md:pt-24 md:pb-28 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          animate="visible"
          className="text-center max-w-5xl mx-auto"
        >
          {/* Small Announcement Badge with Subtle Blue/Cyan Dot */}
          <motion.div variants={sharedFadeUp} className="inline-block mb-6">
            <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full border border-cyan-500/25 bg-cyan-500/[0.06] text-cyan-300 text-xs font-semibold tracking-wider uppercase shadow-[0_0_16px_rgba(6,182,212,0.14)] backdrop-blur-sm">
              <span className="flex h-2 w-2 rounded-full bg-[#06B6D4] animate-pulse" />
              <span>INTELLIGENT WEB APPLICATION SECURITY</span>
            </div>
          </motion.div>

          {/* Main Heading: 3-line cadence with gradient on 'Secure with Confidence.' */}
          <motion.h1
            variants={sharedFadeUp}
            className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight text-white leading-[1.08] max-w-4xl mx-auto"
          >
            Find Vulnerabilities.
            <br />
            Understand the Risk.
            <br />
            <span className="bg-gradient-to-r from-[#06B6D4] via-sky-300 to-[#2563EB] bg-clip-text text-transparent">
              Secure with Confidence.
            </span>
          </motion.h1>

          {/* Subtext: Clear, concise enterprise copy */}
          <motion.p
            variants={sharedFadeUp}
            className="mt-6 text-base sm:text-lg md:text-xl text-[#94A3B8] max-w-2xl mx-auto font-normal leading-relaxed"
          >
            ORION automatically discovers attack surfaces, detects web application vulnerabilities, maps findings to OWASP and CWE, and turns technical evidence into actionable security reports.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            variants={sharedFadeUp}
            className="mt-9 flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <motion.button
              whileHover={shouldReduceMotion ? undefined : { scale: 1.03 }}
              whileTap={shouldReduceMotion ? undefined : { scale: 0.98 }}
              onClick={() => handleAction("signup")}
              className="w-full sm:w-auto h-12 px-8 rounded-full bg-gradient-to-r from-[#2563EB] via-sky-500 to-[#06B6D4] hover:from-[#1d4ed8] hover:to-[#0891b2] text-white font-semibold text-sm shadow-[0_0_28px_rgba(37,99,235,0.4)] flex items-center justify-center gap-2.5 transition-all border border-cyan-400/30"
            >
              <span>Start a Security Scan</span>
              <ArrowRight className="h-4 w-4" />
            </motion.button>
            <motion.a
              href="#how-it-works"
              whileHover={shouldReduceMotion ? undefined : { scale: 1.02 }}
              whileTap={shouldReduceMotion ? undefined : { scale: 0.98 }}
              className="w-full sm:w-auto h-12 px-8 rounded-full bg-[#0B1728] hover:bg-[#0f1f35] border border-white/10 hover:border-white/20 text-[#F8FAFC] hover:text-white font-semibold text-sm flex items-center justify-center gap-2 transition-all shadow-sm"
            >
              <Play className="h-3.5 w-3.5 fill-current text-cyan-400" />
              <span>Explore ORION</span>
            </motion.a>
          </motion.div>

          {/* Subtle sign in prompt below hero CTA */}
          {!isAuthenticated && (
            <motion.div variants={sharedFadeUp} className="mt-4 text-xs text-slate-400">
              Already have an account?{" "}
              <button
                onClick={() => handleAction("login")}
                className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 transition-colors"
              >
                Sign In
              </button>
            </motion.div>
          )}

          {/* ========================================================================= */}
          {/* HERO SECURITY VISUAL (Abstract Scan Visualization) */}
          {/* ========================================================================= */}
          <motion.div
            variants={sharedFadeUp}
            animate={shouldReduceMotion ? undefined : { y: [0, -6, 0] }}
            transition={{
              repeat: Infinity,
              duration: 6,
              ease: "easeInOut",
            }}
            className="mt-16 text-left"
          >
            <div className="relative rounded-2xl border border-white/10 bg-[#0B1728]/90 backdrop-blur-xl p-6 sm:p-8 shadow-[0_20px_70px_rgba(0,0,0,0.6)] overflow-hidden">
              {/* Subtle top header bar inside visualization */}
              <div className="flex flex-wrap items-center justify-between gap-4 pb-6 mb-6 border-b border-white/[0.08]">
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
                  </div>
                  <div className="h-4 w-[1px] bg-white/10" />
                  <span className="font-mono text-xs font-semibold text-slate-300 flex items-center gap-2">
                    <Scan className="h-3.5 w-3.5 text-cyan-400" />
                    ORION EXECUTION PIPELINE TELEMETRY
                  </span>
                </div>
                <div className="flex items-center gap-3 font-mono text-[11px] text-slate-400">
                  <span className="flex items-center gap-1.5 text-cyan-300">
                    <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
                    PIPELINE ACTIVE
                  </span>
                  <span className="hidden sm:inline text-slate-600">•</span>
                  <span className="hidden sm:inline">ZERO-AGENT ARCHITECTURE</span>
                </div>
              </div>

              {/* Connected Pipeline Flow */}
              <div className="relative">
                {/* Connecting track line between nodes (desktop) */}
                <div className="hidden lg:block absolute top-[36px] left-[6%] right-[6%] h-[2px] bg-slate-800 z-0">
                  {/* Animated Traveling Pulse Beam */}
                  {!shouldReduceMotion && (
                    <motion.div
                      className="h-full bg-gradient-to-r from-transparent via-cyan-400 to-transparent w-[30%]"
                      initial={{ x: "-30%" }}
                      animate={{ x: "350%" }}
                      transition={{
                        duration: 3.5,
                        repeat: Infinity,
                        ease: "easeInOut",
                      }}
                    />
                  )}
                </div>

                {/* 5 Interconnected Nodes */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 relative z-10">
                  {PIPELINE_NODES.map((node, index) => {
                    const NodeIcon = node.icon;
                    const isActive = activeVisualNode === index;

                    return (
                      <motion.div
                        key={node.id}
                        onMouseEnter={() => setActiveVisualNode(index)}
                        className={`group relative p-4 rounded-xl border transition-all duration-300 cursor-pointer flex flex-col justify-between ${
                          isActive
                            ? "border-cyan-500/50 bg-[#07111F]/90 shadow-[0_0_30px_rgba(6,182,212,0.18)]"
                            : "border-white/[0.08] bg-[#07111F]/50 hover:border-white/20 hover:bg-[#07111F]/80"
                        }`}
                      >
                        {/* Node Header */}
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <div
                              className={`h-9 w-9 rounded-lg flex items-center justify-center transition-colors ${
                                isActive
                                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                                  : "bg-white/5 text-slate-400 border border-white/10 group-hover:text-white"
                              }`}
                            >
                              <NodeIcon className="h-4 w-4" />
                            </div>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${node.badgeColor}`}
                            >
                              {node.status}
                            </span>
                          </div>

                          <div className="text-[10px] font-mono font-bold tracking-wider text-cyan-400/90 mb-1">
                            {node.phase}
                          </div>
                          <div className="text-xs font-bold text-white leading-snug mb-1">
                            {node.label}
                          </div>
                          <div className="text-[11px] font-medium text-slate-300 truncate">
                            {node.value}
                          </div>
                        </div>

                        {/* Subtle Metadata Detail */}
                        <div className="mt-3 pt-2.5 border-t border-white/[0.06] text-[10.5px] font-mono text-slate-400">
                          {node.detail}
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </div>

              {/* Active Node Live Telemetry Drawer */}
              <div className="mt-6 pt-4 border-t border-white/[0.06] flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-slate-300">
                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                  <span className="text-slate-400">Phase Telemetry:</span>
                  <span className="text-white font-semibold">
                    {PIPELINE_NODES[activeVisualNode].phase}
                  </span>
                  <span className="text-slate-500">→</span>
                  <span className="text-cyan-300">
                    {Object.values(PIPELINE_NODES[activeVisualNode].telemetry).join(" • ")}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500">
                  Sample telemetry values for visual representation
                </div>
              </div>
            </div>
          </motion.div>

          {/* ========================================================================= */}
          {/* ORION CAPABILITIES STRIP */}
          {/* ========================================================================= */}
          <motion.div variants={sharedFadeUp} className="mt-8">
            <div className="p-3 sm:p-4 rounded-2xl border border-white/10 bg-[#0B1728]/70 backdrop-blur-md shadow-sm">
              <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-xs font-semibold text-slate-300">
                {CAPABILITY_STRIP.map((item, idx) => {
                  const ItemIcon = item.icon;
                  return (
                    <div
                      key={item.label}
                      className="flex items-center gap-2 px-2.5 py-1 rounded-lg hover:text-white hover:bg-white/[0.04] transition-colors"
                    >
                      <ItemIcon className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>{item.label}</span>
                      {idx < CAPABILITY_STRIP.length - 1 && (
                        <span className="hidden lg:inline text-slate-700 ml-4">•</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        </motion.div>
      </section>

      {/* ========================================================================= */}
      {/* 3. INTERACTIVE LIVE SCANNER SENSOR DEMO (#how-it-works / #demo) */}
      {/* ========================================================================= */}
      <section id="how-it-works" className="relative z-10 py-16 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-60px" }}
          transition={{ duration: 0.6 }}
          className="rounded-2xl border border-white/15 bg-[#0b1324]/95 shadow-[0_20px_80px_rgba(0,0,0,0.6)] backdrop-blur-2xl overflow-hidden"
        >
          {/* Mock Console Top Bar */}
          <div className="flex flex-wrap items-center justify-between border-b border-white/10 px-5 py-4 bg-[#090f1d]">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-full bg-rose-500/90" />
                <span className="h-3 w-3 rounded-full bg-amber-500/90" />
                <span className="h-3 w-3 rounded-full bg-emerald-500/90" />
              </div>
              <span className="font-mono text-xs text-slate-400 pl-2 border-l border-white/10">
                orion-core-v2.0 :: automated-sensor-feed
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs">
              <button
                onClick={() => setIsPlayingLogs(!isPlayingLogs)}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md font-semibold border transition-all ${
                  isPlayingLogs
                    ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                    : "bg-white/5 text-slate-400 border-white/10 hover:text-white"
                }`}
              >
                <Radio className={`h-3.5 w-3.5 ${isPlayingLogs ? "animate-pulse text-emerald-400" : ""}`} />
                {isPlayingLogs ? "Live Streaming" : "Paused"}
              </button>
              <button
                onClick={() => handleAction("signup")}
                className="text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1"
              >
                Open Real Console <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Console Content Window */}
          <div className="p-6 md:p-8 font-mono text-xs sm:text-sm min-h-[300px] space-y-3">
            <div className="text-cyan-400 font-bold flex items-center gap-2">
              <Terminal className="h-4 w-4" />
              <span>ORION SCAN PIPELINE TELEMETRY :: ACTIVE RUN</span>
            </div>

            <div className="space-y-2 pt-2">
              {terminalLogs.slice(0, terminalLogIndex + 1).map((log, index) => {
                let badgeColor = "text-blue-400";
                if (log.lvl === "FOUND") badgeColor = "text-rose-400 font-bold";
                if (log.lvl === "AI-REPLAY") badgeColor = "text-purple-400";
                if (log.lvl === "PORT") badgeColor = "text-amber-400";
                if (log.lvl === "TLS") badgeColor = "text-cyan-400";
                if (log.lvl === "REPORT") badgeColor = "text-emerald-400 font-bold";

                return (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="flex items-start gap-3 text-slate-300"
                  >
                    <span className="text-slate-500 shrink-0">[{log.time}]</span>
                    <span className={`shrink-0 ${badgeColor}`}>[{log.lvl}]</span>
                    <span className="leading-relaxed">{log.msg}</span>
                  </motion.div>
                );
              })}
            </div>
          </div>

          {/* Bottom Bar inside Terminal */}
          <div className="px-5 py-3.5 border-t border-white/10 bg-[#090f1d] flex flex-wrap items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
              <span>28 Verified Security Engines Running in Parallel</span>
            </div>
            <div className="text-cyan-400 font-semibold cursor-pointer" onClick={() => handleAction("login")}>
              Sign In to trigger scans on custom targets →
            </div>
          </div>
        </motion.div>
      </section>

      {/* ========================================================================= */}
      {/* 4. CORE PLATFORM CAPABILITIES (BENTO GRID - #features) */}
      {/* ========================================================================= */}
      <section id="features" className="relative z-10 py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto border-t border-white/[0.08]">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <motion.span
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-xs font-bold uppercase tracking-widest text-cyan-400"
          >
            Core Capabilities
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-white mt-2"
          >
            Engineered for High-Assurance Cyber Defense
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-slate-400 mt-4 text-base"
          >
            Orion unifies reconnaissance, deep vulnerability detection, and AI remediation into one cohesive platform.
          </motion.p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-cyan-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(14,165,233,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-6 group-hover:scale-110 transition-transform">
              <Globe2 className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Automated Attack Surface Recon</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Enumerate authoritative DNS records (A, AAAA, MX, NS, TXT), perform dictionary subdomain resolution, extract WHOIS registration intel, and map dynamic SPAs with headless Chromium.
            </p>
          </motion.div>

          {/* Card 2 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-blue-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(59,130,246,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-6 group-hover:scale-110 transition-transform">
              <Zap className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">15 Web Injection Engines</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Execute active, non-destructive probing for SQL Injection (Error, Blind, Boolean, UNION), reflected XSS with context analysis, SSRF cloud metadata probes, LFI, XXE, RCE, IDOR, NoSQLi, LDAPI, and SSTI.
            </p>
          </motion.div>

          {/* Card 3 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-indigo-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(99,102,241,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-6 group-hover:scale-110 transition-transform">
              <Code2 className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">API & Modern Protocols</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Audit REST endpoints for risky HTTP TRACE methods and PII leaks. Inspect GraphQL for introspection disclosure and batch abuse, and probe JWT tokens for algorithm 'none' and weak HMAC secrets.
            </p>
          </motion.div>

          {/* Card 4 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-emerald-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(16,185,129,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-6 group-hover:scale-110 transition-transform">
              <Server className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Port, Service & OS Fingerprinting</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Asynchronous TCP port scanner scans common services, grabs service banners, infers the host OS, and cross-references fingerprinted versions against known CVE databases.
            </p>
          </motion.div>

          {/* Card 5 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-purple-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(168,85,247,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-6 group-hover:scale-110 transition-transform">
              <Cpu className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Adaptive Chaining & AI Quality Gate</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Adaptive Engine escalates finding chains into deep tests. Root-cause SHA256 correlation eliminates duplicate noise, while automated HTTP replay confirms High and Critical flaws.
            </p>
          </motion.div>

          {/* Card 6 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="group relative p-8 rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] to-transparent hover:border-cyan-500/40 transition-all duration-300 hover:shadow-[0_12px_40px_rgba(14,165,233,0.15)]"
          >
            <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-6 group-hover:scale-110 transition-transform">
              <FileText className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Executive PDF Security Reports</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Generate publication-grade PDF assessment reports featuring executive scorecards, target information tables, verified methodology breakdowns, and developer remediation fix guides.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* 5. VERIFIED SCAN METHODOLOGY (#reports) */}
      {/* ========================================================================= */}
      <section id="reports" className="relative z-10 py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto border-t border-white/[0.08]">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <motion.span
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-xs font-bold uppercase tracking-widest text-cyan-400"
          >
            Verified Methodology
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl sm:text-4xl font-extrabold text-white mt-2"
          >
            28+ Confirmed Security Checks
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-slate-400 mt-3 text-base"
          >
            Every security check listed below is backed by actual executable scanner modules in the Orion engine. No simulated or inflated claims.
          </motion.p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Category 1 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-cyan-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
              <Search className="h-4 w-4" /> RECONNAISSANCE & DISCOVERY
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" /> DNS Records: A, AAAA, MX, NS, TXT, SOA</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" /> Subdomain Dictionary (45 Prefixes)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" /> WHOIS Registrar & Nameserver Intel</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" /> Web Scope Crawling & Form Harvesting</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" /> Headless Chromium SPA DOM Interception</div>
            </div>
          </motion.div>

          {/* Category 2 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-blue-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-blue-400 font-bold text-sm">
              <Lock className="h-4 w-4" /> TRANSPORT & NETWORK
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-blue-400 shrink-0" /> TLS 1.2+ Protocol Enforcement</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-blue-400 shrink-0" /> Insecure Cipher Suite & Key Length Check</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-blue-400 shrink-0" /> X.509 Certificate Expiration & Trust Chain</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-blue-400 shrink-0" /> Safe Non-Destructive TCP Port Scanning</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-blue-400 shrink-0" /> Service Banner & OS Fingerprinting</div>
            </div>
          </motion.div>

          {/* Category 3 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-indigo-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-indigo-400 font-bold text-sm">
              <ShieldCheck className="h-4 w-4" /> CONFIGURATION & POSTURE
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-indigo-400 shrink-0" /> Content-Security-Policy (CSP) Directives</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-indigo-400 shrink-0" /> HTTP Strict Transport Security (HSTS)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-indigo-400 shrink-0" /> Anti-Clickjacking: XFO & frame-ancestors</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-indigo-400 shrink-0" /> CORS Arbitrary Reflection & Wildcards</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-indigo-400 shrink-0" /> Cookie Security: Secure, HttpOnly, SameSite</div>
            </div>
          </motion.div>

          {/* Category 4 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-rose-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
              <AlertTriangle className="h-4 w-4" /> CORE INJECTION & VULNS
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-rose-400 shrink-0" /> Cross-Site Scripting (XSS Reflection)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-rose-400 shrink-0" /> SQL Injection (Error, Blind, Boolean, UNION)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-rose-400 shrink-0" /> SSRF Cloud Metadata & Loopback Probes</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-rose-400 shrink-0" /> Path Traversal & Local File Inclusion (LFI)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-rose-400 shrink-0" /> Remote Code Execution (RCE) Delimiters</div>
            </div>
          </motion.div>

          {/* Category 5 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-emerald-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
              <Code2 className="h-4 w-4" /> ACCESS CONTROL & APIS
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> Insecure Direct Object References (IDOR)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> Open URL Redirection Parameters</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> REST Method Enumeration & PII Exposure</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> GraphQL Introspection & Depth Abuse</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> JWT Signature 'None' & Secret Dictionary</div>
            </div>
          </motion.div>

          {/* Category 6 */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="p-6 rounded-2xl border border-white/10 bg-[#0a101f]/80 backdrop-blur space-y-4 hover:border-purple-500/30 transition-all duration-300"
          >
            <div className="flex items-center gap-2 text-purple-400 font-bold text-sm">
              <Cpu className="h-4 w-4" /> ADAPTIVE CHAINING & QUALITY
            </div>
            <div className="space-y-2 text-xs text-slate-300">
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-purple-400 shrink-0" /> Adaptive Engine Threat Escalation</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-purple-400 shrink-0" /> Active Evidence Replay for High/Critical</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-purple-400 shrink-0" /> Root-Cause Correlation (SHA256 Keys)</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-purple-400 shrink-0" /> Dynamic CVSS v3.1 Scoring Algorithm</div>
              <div className="flex items-center gap-2"><Check className="h-3.5 w-3.5 text-purple-400 shrink-0" /> Automated CVE Matching on Services</div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* 6. PIPELINE TIMELINE (#platform) */}
      {/* ========================================================================= */}
      <section id="platform" className="relative z-10 py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto border-t border-white/[0.08]">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <motion.span
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-xs font-bold uppercase tracking-widest text-cyan-400"
          >
            How Orion Operates
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl sm:text-4xl font-extrabold text-white mt-2"
          >
            The 3-Step Assessment Architecture
          </motion.h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="p-8 rounded-2xl border border-white/10 bg-[#0d1527]/70 backdrop-blur relative"
          >
            <div className="text-5xl font-black text-cyan-500/20 mb-4">01</div>
            <h3 className="text-xl font-bold text-white mb-2">Scope Ingestion & Safety</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Enter target URL. Select scan mode: <strong>Full Scan</strong> (all 15 injection engines + network checks), <strong>Quick Scan</strong>, or <strong>Compliance</strong>. Orion validates scope boundaries, initializes telemetry cache, and enforces rate limits.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="p-8 rounded-2xl border border-white/10 bg-[#0d1527]/70 backdrop-blur relative"
          >
            <div className="text-5xl font-black text-blue-500/20 mb-4">02</div>
            <h3 className="text-xl font-bold text-white mb-2">Multi-Phase Active Probing</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              Concurrent discovery, Chromium DOM SPA crawling, and active injection testing execute in parallel. The Adaptive Engine detects finding relationships to escalate follow-up checks.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="p-8 rounded-2xl border border-white/10 bg-[#0d1527]/70 backdrop-blur relative"
          >
            <div className="text-5xl font-black text-emerald-500/20 mb-4">03</div>
            <h3 className="text-xl font-bold text-white mb-2">Verification & PDF Export</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              High and Critical flaws undergo automated HTTP evidence replay verification. Root-cause SHA256 deduplication gates results, and executive PDF reports are compiled in seconds.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* 7. FREQUENTLY ASKED QUESTIONS (#about) */}
      {/* ========================================================================= */}
      <section id="about" className="relative z-10 py-20 px-4 sm:px-6 lg:px-8 max-w-4xl mx-auto border-t border-white/[0.08]">
        <div className="text-center mb-16">
          <motion.span
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-xs font-bold uppercase tracking-widest text-cyan-400"
          >
            About Orion & FAQ
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl sm:text-4xl font-extrabold text-white mt-2"
          >
            Answers to Common Questions
          </motion.h2>
        </div>

        <div className="space-y-4">
          {[
            {
              q: "Does Orion perform destructive testing or cause downtime?",
              a: "No. All Orion active probes use safe, bounded test vectors (e.g. arithmetic sleep thresholds, context reflection markers, and non-destructive syntax injection) designed to detect vulnerabilities without corrupting databases or disrupting production services."
            },
            {
              q: "What types of applications can Orion scan?",
              a: "Orion is purpose-built for modern web architectures: Traditional Multi-Page Applications (MPAs), Single-Page Applications (React, Vue, Angular) via headless Chromium DOM crawling, REST APIs, and GraphQL endpoints."
            },
            {
              q: "How does the Finding Quality Pipeline eliminate false positives?",
              a: "Every raw detection must meet strict evidence criteria (e.g. status code changes, reflected payloads, or header proofs). High and Critical findings undergo automated HTTP evidence replay verification before final confirmation."
            },
            {
              q: "Can I export reports for security audits or SOC2 compliance?",
              a: "Yes. Orion generates publication-grade PDF assessment reports including Executive Scorecards (A-F), target details, verified methodology descriptions, finding evidence dumps, and developer remediation fix guides."
            }
          ].map((faq, index) => {
            const isOpen = activeFaq === index;
            return (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 15 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
                className="border border-white/10 rounded-xl bg-[#0a1120]/80 overflow-hidden"
              >
                <button
                  onClick={() => setActiveFaq(isOpen ? null : index)}
                  className="w-full p-5 text-left flex items-center justify-between gap-4 font-semibold text-white hover:text-cyan-400 transition-colors"
                >
                  <span className="text-sm sm:text-base">{faq.q}</span>
                  <ChevronDown className={`h-4 w-4 shrink-0 transition-transform ${isOpen ? "rotate-180 text-cyan-400" : "text-slate-400"}`} />
                </button>
                <AnimatePresence>
                  {isOpen && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="px-5 pb-5 text-xs sm:text-sm text-slate-400 leading-relaxed border-t border-white/5 pt-3"
                    >
                      {faq.a}
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* 8. CALL TO ACTION BANNER */}
      {/* ========================================================================= */}
      <section className="relative z-10 py-20 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="relative rounded-3xl p-10 sm:p-14 text-center border border-cyan-500/30 bg-gradient-to-br from-[#0c162c] via-[#081020] to-[#040810] shadow-[0_20px_90px_rgba(6,182,212,0.18)] overflow-hidden"
        >
          <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />
          <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[100px] pointer-events-none" />

          <h2 className="text-3xl sm:text-4xl md:text-5xl font-black text-white tracking-tight">
            Assess Your Attack Surface Today
          </h2>
          <p className="mt-4 text-sm sm:text-base text-slate-300 max-w-xl mx-auto">
            Run an automated, non-destructive vulnerability scan against your domain in under 3 minutes.
          </p>

          <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button
              onClick={() => handleAction("signup")}
              className="w-full sm:w-auto h-12 px-8 rounded-full bg-gradient-to-r from-[#2563EB] to-[#06B6D4] hover:from-[#1d4ed8] hover:to-[#0891b2] text-white font-bold text-sm shadow-[0_0_30px_rgba(6,182,212,0.35)] flex items-center justify-center gap-2 border border-cyan-400/30"
            >
              Start Free Assessment <ArrowRight className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              onClick={() => handleAction("login")}
              className="w-full sm:w-auto h-12 px-8 rounded-full border-white/10 hover:border-white/20 bg-[#0B1728] text-white font-semibold text-sm"
            >
              Sign In to Account
            </Button>
          </div>
        </motion.div>
      </section>

      {/* ========================================================================= */}
      {/* 9. FOOTER */}
      {/* ========================================================================= */}
      <footer className="relative z-10 border-t border-white/[0.08] bg-[#050b15] py-12 px-4 sm:px-6 lg:px-8 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 overflow-hidden">
              <img src="/orion-logo.png" alt="Orion" className="h-full w-full object-cover" />
            </div>
            <div>
              <div className="text-sm font-bold text-white tracking-wide">ORION</div>
              <div className="text-[10px] text-slate-500">Intelligent Web Application Security Platform</div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 font-medium">
            <a href="#platform" className="hover:text-white transition-colors">Platform</a>
            <a href="#features" className="hover:text-white transition-colors">Features</a>
            <a href="#how-it-works" className="hover:text-white transition-colors">How It Works</a>
            <a href="#reports" className="hover:text-white transition-colors">Reports</a>
            <a href="#about" className="hover:text-white transition-colors">About</a>
            <button onClick={() => handleAction("login")} className="hover:text-white transition-colors">Sign In</button>
            <button onClick={() => handleAction("signup")} className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">Sign Up</button>
          </div>

          <div className="text-center md:text-right text-slate-400">
            © {new Date().getFullYear()} ORION Security Systems. Built for high-assurance cybersecurity.
          </div>
        </div>
      </footer>
    </div>
  );
}
