import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { ShieldCheck, MailCheck, AlertCircle, CheckCircle2, ArrowRight, RefreshCw, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { verifyEmail, resendVerification } from "@/services/api";

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const tokenParam = searchParams.get("token") || "";
  const emailParam = searchParams.get("email") || "";

  const [token, setToken] = useState(tokenParam);
  const [resendEmail, setResendEmail] = useState(emailParam);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const hasAutoVerified = useRef(false);

  // Auto-verify once if token is provided in URL
  useEffect(() => {
    if (tokenParam && !hasAutoVerified.current) {
      hasAutoVerified.current = true;
      handleVerify(tokenParam);
    }
  }, [tokenParam]);

  useEffect(() => {
    if (emailParam) {
      setResendEmail(emailParam);
    }
  }, [emailParam]);

  const handleVerify = async (tokenToVerify: string) => {
    const cleanToken = tokenToVerify.trim();
    if (!cleanToken) {
      setStatusMessage(null);
      setErrorMessage("Please enter a valid verification token.");
      return;
    }

    setErrorMessage(null);
    setStatusMessage(null);
    setIsVerifying(true);

    try {
      const response = await verifyEmail(cleanToken, resendEmail);
      setErrorMessage(null);
      setIsSuccess(true);
      setStatusMessage(response.message || "Email verified successfully! You can now log in to ORION.");
    } catch (err: any) {
      setStatusMessage(null);
      setIsSuccess(false);
      const detail = err.response?.data?.detail;
      setErrorMessage(typeof detail === "string" ? detail : "Verification failed or token expired.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanEmail = resendEmail.trim();
    if (!cleanEmail) {
      setStatusMessage(null);
      setErrorMessage("Please enter your email to resend verification link.");
      return;
    }

    setErrorMessage(null);
    setStatusMessage(null);
    setIsResending(true);

    try {
      setErrorMessage(null);
      const response = await resendVerification(cleanEmail);
      if (response.already_verified) {
        setIsSuccess(true);
        setStatusMessage(response.message || "This account is already verified! You can proceed to sign in.");
        return;
      }
      setStatusMessage(response.message || "Verification email sent. Check your inbox.");
      if ((import.meta as any).env?.DEV && response.dev_token) {
        console.info("[ORION DEV ONLY] Resent Verification OTP:", response.dev_token);
      }
    } catch (err: any) {
      setStatusMessage(null);
      const detail = err.response?.data?.detail;
      setErrorMessage(typeof detail === "string" ? detail : "Failed to resend verification email.");
    } finally {
      setIsResending(false);
    }
  };

  return (
    <main className="relative min-h-screen bg-[#020817] text-white flex items-center justify-center p-4">
      {/* Background grid */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(120,119,198,0.15),rgba(255,255,255,0))] pointer-events-none" />

      <div className="w-full max-w-md bg-slate-900/80 border border-slate-800 backdrop-blur-xl rounded-2xl p-8 shadow-2xl relative z-10">
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-wider">ORION</h1>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Account Verification</p>
          </div>
        </div>

        {isSuccess ? (
          <div className="text-center py-4 space-y-5">
            <div className="w-16 h-16 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded-full flex items-center justify-center mx-auto animate-bounce">
              <CheckCircle2 className="h-9 w-9" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Verification Confirmed</h2>
              <p className="text-sm text-slate-300 mt-2">{statusMessage}</p>
            </div>
            <Button
              className="w-full bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold py-6 text-base"
              onClick={() => navigate("/login")}
            >
              Proceed to Sign In <ArrowRight className="h-5 w-5 ml-2" />
            </Button>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="text-center">
              <div className="w-14 h-14 bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-full flex items-center justify-center mx-auto mb-3">
                <MailCheck className="h-7 w-7" />
              </div>
              <h2 className="text-xl font-bold text-white">Enter Verification OTP</h2>
              <p className="text-xs text-slate-400 mt-1">
                {resendEmail ? (
                  <>We sent a 6-digit verification code to <span className="text-cyan-400 font-semibold">{resendEmail}</span></>
                ) : (
                  "Please enter the 6-digit OTP sent to your registered email."
                )}
              </p>
            </div>

            {errorMessage && (
              <div className="flex items-start gap-3 p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
                <AlertCircle className="h-5 w-5 shrink-0 mt-0.5 text-rose-400" />
                <span>{errorMessage}</span>
              </div>
            )}

            {statusMessage && (
              <div className="flex items-start gap-3 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-sm">
                <CheckCircle2 className="h-5 w-5 shrink-0 mt-0.5 text-emerald-400" />
                <span>{statusMessage}</span>
              </div>
            )}

            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleVerify(token);
              }}
              className="space-y-4"
            >
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1.5 text-center">
                  6-Digit One-Time Passcode (OTP)
                </label>
                <div className="relative">
                  <KeyRound className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                  <Input
                    type="text"
                    inputMode="numeric"
                    maxLength={10}
                    placeholder="Enter 6-digit OTP"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    className="bg-slate-950/60 border-slate-800 text-white pl-10 text-center font-mono tracking-[0.3em] text-lg font-bold focus:border-cyan-500"
                  />
                </div>
              </div>

              <Button
                type="submit"
                disabled={isVerifying || !token.trim()}
                className="w-full bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-bold py-5"
              >
                {isVerifying ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin mr-2" /> Verifying OTP...
                  </>
                ) : (
                  "Verify OTP"
                )}
              </Button>
            </form>

            {/* Resend section */}
            <div className="pt-4 border-t border-slate-800/80">
              <p className="text-xs text-slate-400 text-center mb-3">Didn't receive the OTP email or code expired?</p>
              <form onSubmit={handleResend} className="flex gap-2">
                <Input
                  type="email"
                  value={resendEmail}
                  disabled
                  readOnly
                  placeholder="Registered email"
                  className="bg-slate-950/40 border-slate-800 text-slate-400 text-xs cursor-not-allowed select-none opacity-75 focus-visible:ring-0 focus:border-slate-800"
                />
                <Button
                  type="submit"
                  disabled={isResending || !resendEmail.trim()}
                  variant="outline"
                  className="border-slate-700 hover:bg-slate-800 text-xs shrink-0"
                >
                  {isResending ? <RefreshCw className="h-3 w-3 animate-spin" /> : "Resend OTP"}
                </Button>
              </form>
            </div>

            <div className="text-center pt-2">
              <Link to="/login" className="text-xs text-slate-400 hover:text-cyan-400 transition-colors">
                Back to Sign In
              </Link>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
