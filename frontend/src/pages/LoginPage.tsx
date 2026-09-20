import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Scan, Activity, BarChart3, ArrowRight, Eye, EyeOff, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { login, register } from "@/services/api";

export function LoginPage() {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [isSignUp, setIsSignUp] = useState(false);

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
        const queryParams = new URLSearchParams({ email: cleanEmail });
        if (regRes?.dev_token) {
          queryParams.set("token", regRes.dev_token);
        }
        // Navigate directly to verify-email without issuing session
        navigate(`/verify-email?${queryParams.toString()}`);
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
        navigate("/");
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
    <main className="relative min-h-screen bg-[#020817] text-white flex items-center justify-center overflow-hidden login-bg-grid">
      {/* Scanning Animation Line */}
      <div className="scan-line-animation" />

      <div className="container max-w-6xl mx-auto flex flex-col lg:flex-row items-center justify-between p-8 gap-12 z-10">
        
        {/* Left Side Content */}
        <div className="flex-1 max-w-xl">
          <div className="flex items-center gap-3 mb-10">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/20 text-indigo-400">
              <ShieldCheck className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-wider">ORION</h1>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-indigo-400">AI Security Desk</p>
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