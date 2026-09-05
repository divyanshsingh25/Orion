import type React from "react";
import { cn } from "@/utils/cn";

interface SectionCardProps {
  title: string;
  subtitle?: string;
  eyebrow?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  contentClassName?: string;
}

export function SectionCard({ title, subtitle, eyebrow, icon, children, className, contentClassName }: SectionCardProps) {
  return (
    <section data-pet-obstacle="true" className={cn("panel group relative overflow-hidden", className)}>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent opacity-70" />
      <div className="flex items-start justify-between px-6 pt-6">
        <div>
          {eyebrow ? <div className="section-label mb-3">{eyebrow}</div> : null}
          <h2 className="text-[20px] font-bold leading-none tracking-[-0.01em]">{title}</h2>
          {subtitle ? <p className="mt-2.5 text-[15px] font-semibold text-muted-foreground">{subtitle}</p> : null}
        </div>
        {icon ? <div className="rounded-xl border border-border/70 bg-card/70 p-2 text-muted-foreground shadow-sm">{icon}</div> : null}
      </div>
      <div className={cn("px-6 pb-6", contentClassName)}>{children}</div>
    </section>
  );
}