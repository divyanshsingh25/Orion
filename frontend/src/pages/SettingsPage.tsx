import { useEffect, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useCurrentUser } from "@/hooks/useCurrentUser";
import { updateProfile } from "@/services/api";
import { CheckCircle2, AlertCircle } from "lucide-react";

const profileSchema = z.object({
  name: z.string().min(1, "Full name is required"),
  username: z.string().min(3, "Username must be at least 3 characters").max(30),
  email: z.string().email(),
  organization: z.string().min(2),
});

type ProfileForm = z.infer<typeof profileSchema>;

export function SettingsPage() {
  const { user } = useCurrentUser();
  const [isSaving, setIsSaving] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const defaultValues: ProfileForm = {
    name: user?.full_name || user?.username || "",
    username: user?.username || "",
    email: user?.email || "",
    organization: user?.organization || "",
  };

  const { register, handleSubmit, reset, formState: { errors } } = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues,
  });

  // Sync form when user profile loads or changes
  useEffect(() => {
    if (user) {
      reset({
        name: user.full_name || user.username || "",
        username: user.username || "",
        email: user.email || "",
        organization: user.organization || "",
      });
    }
  }, [user, reset]);

  const onSubmit = async (data: ProfileForm) => {
    setIsSaving(true);
    setSuccessMessage(null);
    setErrorMessage(null);
    try {
      await updateProfile({
        full_name: data.name,
        username: data.username,
        organization: data.organization,
      });
      setSuccessMessage("Profile updated successfully!");
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || "Failed to update profile";
      setErrorMessage(typeof detail === "string" ? detail : JSON.stringify(detail));
    } finally {
      setIsSaving(false);
    }
  };

  const getInitials = (name: string) => {
    const clean = name.trim();
    if (!clean) return "U";
    const parts = clean.split(/\s+/);
    if (parts.length === 1) return parts[0].substring(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  };

  const currentDisplayName = user?.full_name || user?.username || "Security User";
  const currentEmail = user?.email || "user@orion.sec";
  const role = user?.username === "admin" ? "Security Admin" : "Security Analyst";

  return (
    <div className="max-w-[1120px]">
      <section className="panel px-[30px] pb-[30px] pt-[29px]">
        <h1 className="text-[20px] font-extrabold">Profile</h1>
        <p className="mt-2 text-[17px] font-medium text-muted-foreground">Your account information</p>

        <div className="mt-[32px] flex items-center gap-[30px] border-b border-border pb-[30px]">
          <div className="flex h-[100px] w-[100px] items-center justify-center rounded-full bg-gradient-to-br from-sky-500 to-indigo-600 text-[30px] font-extrabold text-white shadow-lg">
            {getInitials(currentDisplayName)}
          </div>
          <div>
            <div className="text-[24px] font-extrabold leading-none">{currentDisplayName}</div>
            <div className="mt-2 text-[17px] font-medium text-muted-foreground">{currentEmail}</div>
            <div className="mt-2 text-[15px] font-medium text-indigo-400 font-semibold">{role}</div>
          </div>
        </div>

        {successMessage && (
          <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-sm font-medium text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successMessage}</span>
          </div>
        )}

        {errorMessage && (
          <div className="mt-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-sm font-medium text-rose-400 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit(onSubmit)} className="mt-[28px] space-y-[18px]">
          <div>
            <label className="mb-2 block text-[16px] font-bold">Full Name</label>
            <Input {...register("name")} placeholder="Your full name" />
            {errors.name && <p className="mt-1 text-xs text-rose-500">{errors.name.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-[16px] font-bold">Username</label>
            <Input {...register("username")} placeholder="Your username" />
            {errors.username && <p className="mt-1 text-xs text-rose-500">{errors.username.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-[16px] font-bold">Email</label>
            <Input {...register("email")} disabled className="opacity-70 cursor-not-allowed" title="Email cannot be changed" />
          </div>
          <div>
            <label className="mb-2 block text-[16px] font-bold">Organization</label>
            <Input {...register("organization")} />
            {errors.organization && <p className="mt-1 text-xs text-rose-500">{errors.organization.message}</p>}
          </div>
          <Button disabled={isSaving} className="h-[48px] px-5 text-[16px]">
            {isSaving ? "Saving..." : "Save Changes"}
          </Button>
        </form>
      </section>

      <section className="panel mt-[30px] px-[30px] pb-[30px] pt-[29px]">
        <h2 className="text-[20px] font-extrabold">Notifications</h2>
        <p className="mt-2 text-[17px] font-medium text-muted-foreground">Configure how you receive alerts</p>
      </section>
    </div>
  );
}