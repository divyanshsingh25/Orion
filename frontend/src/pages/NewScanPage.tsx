import { zodResolver } from "@hookform/resolvers/zod";
import { Play, ChevronDown, ChevronRight, Lock, KeyRound } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/ui/select";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { launchAssessment } from "@/services/api";

const scanSchema = z.object({
  targetUrl: z.string().url(),
});

type ScanForm = z.infer<typeof scanSchema>;

export function NewScanPage() {
  const queryClient = useQueryClient();
  const [scanType, setScanType] = useState("Full Scan");
  const [scanDepth, setScanDepth] = useState("Medium");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [authType, setAuthType] = useState("None");

  // Auth fields
  const [cookies, setCookies] = useState("");
  const [bearerToken, setBearerToken] = useState("");
  const [apiKeyHeader, setApiKeyHeader] = useState("X-API-Key");
  const [apiKeyValue, setApiKeyValue] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const navigate = useNavigate();
  const { register, handleSubmit } = useForm<ScanForm>({
    resolver: zodResolver(scanSchema),
    defaultValues: { targetUrl: "" },
  });

  const buildAuthConfig = () => {
    if (!showAuth || authType === "None") return null;
    if (authType === "Cookie") {
      return { auth_type: "cookie", cookies };
    }
    if (authType === "Bearer Token") {
      return { auth_type: "bearer", token: bearerToken };
    }
    if (authType === "API Key Header") {
      return { auth_type: "api_key", header_name: apiKeyHeader, api_key: apiKeyValue };
    }
    if (authType === "Form Login") {
      return {
        auth_type: "form",
        login_url: loginUrl,
        username: loginUsername,
        password: loginPassword,
      };
    }
    return null;
  };

  return (
    <div className="mx-auto max-w-[840px] pt-0">
      <h1 className="text-[37px] font-extrabold leading-none">New Security Scan</h1>
      <p className="muted-copy mt-4">Configure and launch a comprehensive security assessment</p>

      <form
        onSubmit={handleSubmit(async (values) => {
          setIsSubmitting(true);
          try {
            const authConfig = buildAuthConfig();
            const assessment = await launchAssessment({
              targetUrl: values.targetUrl,
              scanType,
              depth: scanDepth,
              authConfig,
            });
            window.localStorage.setItem("orion.active_scan_id", assessment.scan.id);
            window.localStorage.setItem("orion.active_target", values.targetUrl);
            queryClient.invalidateQueries({ queryKey: ["active-scan"] });
            navigate(`/live-scan?scanId=${assessment.scan.id}&target=${encodeURIComponent(values.targetUrl)}`);
          } finally {
            setIsSubmitting(false);
          }
        })}
        className="panel mt-8 px-[30px] pb-[30px] pt-[29px]"
      >
        <h2 className="text-[20px] font-extrabold">Scan Configuration</h2>
        <p className="mt-2 text-[17px] font-medium text-muted-foreground">Define your scan target and parameters</p>

        <div className="mt-9">
          <label className="mb-2 block text-[17px] font-bold">Target URL</label>
          <Input placeholder="https://example.com" {...register("targetUrl")} />
          <p className="mt-3 text-[15px] font-medium text-muted-foreground">Enter the base URL of the application to scan</p>
        </div>

        <div className="mt-9 grid grid-cols-2 gap-[30px]">
          <div>
            <label className="mb-2 block text-[17px] font-bold">Scan Type</label>
            <SelectField value={scanType} onChange={setScanType} options={["Full Scan", "Quick Scan", "Compliance"]} />
          </div>
          <div>
            <label className="mb-2 block text-[17px] font-bold">Scan Depth</label>
            <SelectField value={scanDepth} onChange={setScanDepth} options={["Low", "Medium", "High"]} />
          </div>
        </div>

        {/* Collapsible Authentication Section */}
        <div className="mt-8 border-t border-border pt-6">
          <button
            type="button"
            onClick={() => setShowAuth((prev) => !prev)}
            className="flex w-full items-center justify-between text-left text-[16px] font-bold text-foreground transition hover:opacity-80"
          >
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-primary" />
              <span>Target Authentication (Optional)</span>
            </div>
            {showAuth ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
          </button>

          {showAuth && (
            <div className="mt-5 space-y-5 rounded-lg border border-border/50 bg-secondary/20 p-5">
              <div>
                <label className="mb-2 block text-[15px] font-semibold">Authentication Scheme</label>
                <SelectField
                  value={authType}
                  onChange={setAuthType}
                  options={["None", "Cookie", "Bearer Token", "API Key Header", "Form Login"]}
                />
              </div>

              {authType === "Cookie" && (
                <div>
                  <label className="mb-2 block text-[15px] font-semibold">Session Cookie(s)</label>
                  <Input
                    placeholder="sessionid=abc123xyz; token=eyJhbGciOi..."
                    value={cookies}
                    onChange={(e) => setCookies(e.target.value)}
                  />
                  <p className="mt-1 text-[13px] text-muted-foreground">Semicolon-separated name=value pairs</p>
                </div>
              )}

              {authType === "Bearer Token" && (
                <div>
                  <label className="mb-2 block text-[15px] font-semibold">Bearer Token / JWT</label>
                  <Input
                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    value={bearerToken}
                    onChange={(e) => setBearerToken(e.target.value)}
                  />
                  <p className="mt-1 text-[13px] text-muted-foreground">Will be sent as Authorization: Bearer &lt;token&gt;</p>
                </div>
              )}

              {authType === "API Key Header" && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="mb-2 block text-[15px] font-semibold">Header Name</label>
                    <Input
                      placeholder="X-API-Key"
                      value={apiKeyHeader}
                      onChange={(e) => setApiKeyHeader(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-[15px] font-semibold">API Key Value</label>
                    <Input
                      placeholder="secret-key-value"
                      value={apiKeyValue}
                      onChange={(e) => setApiKeyValue(e.target.value)}
                    />
                  </div>
                </div>
              )}

              {authType === "Form Login" && (
                <div className="space-y-4">
                  <div>
                    <label className="mb-2 block text-[15px] font-semibold">Login URL (Optional)</label>
                    <Input
                      placeholder="https://example.com/login"
                      value={loginUrl}
                      onChange={(e) => setLoginUrl(e.target.value)}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="mb-2 block text-[15px] font-semibold">Username / Email</label>
                      <Input
                        placeholder="admin@example.com"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                      />
                    </div>
                    <div>
                      <label className="mb-2 block text-[15px] font-semibold">Password</label>
                      <Input
                        type="password"
                        placeholder="••••••••"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <Button type="submit" className="mt-10 h-[46px] w-full text-[16px]" disabled={isSubmitting}>
          <Play className="h-5 w-5" />
          {isSubmitting ? "Launching..." : "Start Scan"}
        </Button>
      </form>
    </div>
  );
}