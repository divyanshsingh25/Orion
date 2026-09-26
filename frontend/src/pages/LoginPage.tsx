import { useState, useEffect } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, Scan, Activity, BarChart3, ArrowRight, Eye, EyeOff, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { login, register } from "@/services/api";

export function LoginPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialMode = searchParams.get("mode");
  const initialSignUp = initialMode === "signup" || searchParams.get("signup") === "true";
  
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [isSignUp, setIsSignUp] = useState(initialSignUp);

  useEffect(() => {
    const mode = searchParams.get("mode");
    const isSignupParam = mode === "signup" || searchParams.get("signup") === "true";
    if (isSignupParam) {
      setIsSignUp(true);
    } else if (mode === "login") {
      setIsSignUp(false);
    }
  }, [searchParams]);

  // Form states (no hardcoded passwords or prefilled credentials)
  const [identifier, setIdentifier] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");
  const [organization, setOrganization] = useState("");
  const [password, setPassword] = useState("");

  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);

  const handleToggleMode = () => {
    setIsSignUp(!isSignUp);
    setError(null);
    setUnverifiedEmail(null);
    setPassword("");
    setIdentifier("");
    setEmail("");
    setUsername("");
    setFullName("");
    setOrganization("");
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setUnverifiedEmail(null);
    setIsSubmitting(true);

    try {
      if (isSignUp) {
        const cleanEmail = email.trim();
        const cleanUsername = username.trim();
        const cleanFullName = fullName.trim();
        const cleanOrganization = organization.trim();

        if (!cleanEmail) {
          setError("Email is required.");
          return;
        }
        if (!cleanUsername) {
          setError("Username is required (3-30 characters).");
          return;
        }
        if (!cleanFullName) {
          setError("Full name is required.");
          return;
        }
        if (!cleanOrganization) {
          setError("Organization is required.");
          return;
        }
        if (!password || password.length < 8) {
          setError("Password must be at least 8 characters.");
          return;
        }

        const regRes = await register(cleanEmail, password, cleanUsername, cleanFullName, cleanOrganization);
        if ((import.meta as any).env?.DEV && regRes?.dev_token) {
          console.info("[ORION DEV ONLY] Verification OTP:", regRes.dev_token);
        }
        // Always navigate with only the email parameter so the user must enter the OTP received in their email
        navigate(`/verify-email?email=${encodeURIComponent(cleanEmail)}`);
      } else {
        const cleanIdentifier = identifier.trim();
        if (!cleanIdentifier) {
          setError("Email or username is required.");
          return;
        }
        if (!password) {
          setError("Password is required.");
          return;
        }

        await login(cleanIdentifier, password);
        navigate("/dashboard");
      }
    } catch (submissionError: any) {
      const code = submissionError?.response?.data?.code;
      if (code === "EMAIL_NOT_VERIFIED") {
        setUnverifiedEmail(isSignUp ? email.trim() : identifier.trim());
        setError("Email verification required. Your account must be verified before logging in to ORION.");
        return;
      }

      let errorMessage = `Unable to ${isSignUp ? "sign up" : "sign in"}`;

      if (submissionError?.response?.data?.detail) {
        const detail = submissionError.response.data.detail;
        if (Array.isArray(detail)) {
          errorMessage = detail.map((d: any) => `${d.loc[d.loc.length - 1]}: ${d.msg}`).join(", ");
        } else if (typeof detail === "string") {
          errorMessage = detail;
        }
      } else if (submissionError?.response?.data?.message) {
        errorMessage = submissionError.response.data.message;
      } else if (submissionError?.message === "Network Error") {
        errorMessage = "Network Error: Unable to reach the backend API. Please verify the backend is running and CORS allows this origin.";
      } else if (submissionError instanceof Error) {
        errorMessage = submissionError.message;
      }

      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="relative min-h-screen bg-[#07111F] text-[#F8FAFC] flex items-center justify-center overflow-hidden selection:bg-[#06B6D4] selection:text-black">
      {/* Full-Viewport Cybersecurity Background with Animated Scanning Line Effect */}
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
          <g strokeWidth="0.8" strokeDasharray="3 3">
            <line x1="12%" y1="18%" x2="28%" y2="28%" />
            <line x1="28%" y1="28%" x2="45%" y2="20%" />
            <line x1="45%" y1="20%" x2="62%" y2="32%" />
            <line x1="62%" y1="32%" x2="80%" y2="22%" />
            <line x1="80%" y1="22%" x2="92%" y2="35%" />
            <line x1="28%" y1="28%" x2="35%" y2="48%" />
            <line x1="62%" y1="32%" x2="70%" y2="52%" />
          </g>
          <circle cx="12%" cy="18%" r="3" fill="#2563EB" opacity="0.6" />
          <circle cx="28%" cy="28%" r="3.5" fill="#06B6D4" opacity="0.8" />
          <circle cx="45%" cy="20%" r="2.5" fill="#2563EB" opacity="0.5" />
          <circle cx="62%" cy="32%" r="4" fill="#06B6D4" opacity="0.8" />
          <circle cx="80%" cy="22%" r="3" fill="#2563EB" opacity="0.6" />
          <circle cx="92%" cy="35%" r="3" fill="#06B6D4" opacity="0.7" />
          <circle cx="35%" cy="48%" r="2.5" fill="#2563EB" opacity="0.5" />
          <circle cx="70%" cy="52%" r="3" fill="#06B6D4" opacity="0.6" />
        </svg>

        {/* Subtle Animated Scanning Beam traversing the viewport */}
        <motion.div
          className="absolute left-0 right-0 h-[1.5px] bg-gradient-to-r from-transparent via-cyan-400/25 to-transparent pointer-events-none"
          initial={{ y: "0vh" }}
          animate={{ y: "100vh" }}
          transition={{
            duration: 12,
            repeat: Infinity,
            ease: "linear",
          }}
        />
      </div>

      <div className="container max-w-6xl mx-auto flex flex-col lg:flex-row items-center justify-between p-8 gap-12 z-10 relative">
        
        {/* Left Side Content */}
        <div className="flex-1 max-w-xl">
          <Link
            to="/"
            className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-cyan-400 transition-colors mb-6 py-1.5 px-3 rounded-lg border border-white/10 bg-white/[0.03] hover:bg-white/[0.08]"
          >
            ← Back to Home
          </Link>
          <div className="flex items-center gap-3 mb-10">
            <div className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-[#2563EB]/25 to-[#06B6D4]/25 border border-cyan-500/30 shadow-[0_0_18px_rgba(6,182,212,0.22)] overflow-hidden">
              <img src="/orion-logo.png" alt="ORION Logo" className="h-full w-full object-cover scale-110" />
              <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border border-[#07111F] bg-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight text-white">ORION</h1>
              <p className="text-[10px] font-semibold uppercase tracking-widest text-[#94A3B8]">Security Intelligence</p>
            </div>
          </div>

          <h2 className="text-[42px] font-bold leading-tight mb-6">
            Secure your <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">entire attack surface</span>
          </h2>

          <p className="text-slate-400 text-lg mb-10 leading-relaxed max-w-md">
            AI-driven vulnerability scanning, real-time threat intelligence, and guided remediation — all in one desk.
          </p>

          <div className="space-y-6 mb-10">
            <div className="flex items-start gap-4">
              <div className="mt-1 p-2 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <Scan className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="font-bold text-slate-200">AI-Powered Scanning</h3>
                <p className="text-sm text-slate-400 mt-1">Detect vulnerabilities across your entire attack surface in minutes.</p>
              </div>
            </div>
            
            <div className="flex items-start gap-4">
              <div className="mt-1 p-2 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <Activity className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="font-bold text-slate-200">Real-Time Monitoring</h3>
                <p className="text-sm text-slate-400 mt-1">Live threat feeds with instant alerts for critical findings.</p>
              </div>
            </div>

            <div className="flex items-start gap-4">
              <div className="mt-1 p-2 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <BarChart3 className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="font-bold text-slate-200">Actionable Insights</h3>
                <p className="text-sm text-slate-400 mt-1">CVSS-ranked findings with step-by-step remediation guidance.</p>
              </div>
            </div>
          </div>

          <div className="inline-flex items-center gap-4 bg-emerald-950/30 border border-emerald-900/50 rounded-xl p-4">
            <div className="text-3xl font-black text-emerald-400">95</div>
            <div>
              <div className="text-xs font-bold text-emerald-400 tracking-wider">EXCELLENT</div>
              <div className="text-sm text-slate-400">Latest security posture score</div>
            </div>
          </div>
        </div>

        {/* Right Side Login Form */}
        <div className="w-full max-w-[440px]">
          <div className="bg-[#0f172a]/80 backdrop-blur-xl border border-slate-800 rounded-2xl p-8 shadow-2xl">
            <h2 className="text-2xl font-bold text-white mb-2">
              {isSignUp ? "Create an account" : "Welcome back"}
            </h2>
            <p className="text-slate-400 mb-6">
              {isSignUp ? "Sign up for your security desk" : "Sign in to your security desk"}
            </p>

            <form onSubmit={handleSubmit}>
              <div className="space-y-4">
                {isSignUp ? (
                  <>
                    <div>
                      <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                        Email <span className="text-rose-400">*</span>
                      </label>
                      <Input
                        name="email"
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500"
                        placeholder="Enter your email"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                        Username <span className="text-rose-400">*</span> <span className="text-slate-500 font-normal normal-case">(3-30 characters)</span>
                      </label>
                      <Input
                        name="username"
                        type="text"
                        required
                        minLength={3}
                        maxLength={30}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500"
                        placeholder="Enter your username"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                        Full Name <span className="text-rose-400">*</span>
                      </label>
                      <Input
                        name="fullName"
                        type="text"
                        required
                        minLength={1}
                        maxLength={100}
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500"
                        placeholder="Enter your full name"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                        Organization <span className="text-rose-400">*</span>
                      </label>
                      <Input
                        name="organization"
                        type="text"
                        required
                        minLength={1}
                        maxLength={100}
                        value={organization}
                        onChange={(e) => setOrganization(e.target.value)}
                        className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500"
                        placeholder="Enter your organization or company"
                      />
                    </div>
                  </>
                ) : (
                  <div>
                    <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                      Email or Username <span className="text-rose-400">*</span>
                    </label>
                    <Input
                      name="identifier"
                      required
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500"
                      placeholder="Enter your email or username"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                    Password <span className="text-rose-400">*</span> {isSignUp && <span className="text-slate-500 font-normal normal-case">(min 8 characters)</span>}
                  </label>
                  <div className="relative">
                    <Input
                      name="password"
                      type={showPassword ? "text" : "password"}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="bg-[#1e293b]/50 border-slate-700 text-white h-11 focus-visible:ring-indigo-500 pr-10"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-sm font-medium text-rose-400 flex items-start gap-2">
                      <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>{error}</span>
                    </div>
                    {unverifiedEmail && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => navigate(`/verify-email?email=${encodeURIComponent(unverifiedEmail)}`)}
                        className="w-full bg-cyan-950/40 border-cyan-500/40 text-cyan-300 hover:bg-cyan-900/50 hover:text-white text-xs font-semibold py-2 h-auto"
                      >
                        Enter Verification Code / Resend Email <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
                      </Button>
                    )}
                  </div>
                )}

                <Button
                  className="w-full h-11 bg-indigo-600 hover:bg-indigo-500 text-white text-base font-semibold transition-colors mt-2"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    isSignUp ? "Creating account..." : "Signing In..."
                  ) : (
                    <div className="flex items-center gap-2">
                      {isSignUp ? "Sign Up" : "Sign In"} <ArrowRight className="h-4 w-4" />
                    </div>
                  )}
                </Button>
              </div>
            </form>

            <div className="mt-6 text-center text-sm text-slate-400">
              {isSignUp ? "Already have an account? " : "Don't have an account? "}
              <button
                type="button"
                onClick={handleToggleMode}
                className="text-indigo-400 font-semibold hover:text-indigo-300"
              >
                {isSignUp ? "Sign in" : "Create one free"}
              </button>
            </div>
          </div>
        </div>

      </div>
    </main>
  );
}