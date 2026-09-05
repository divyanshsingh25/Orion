import * as React from "react";
import { cn } from "@/utils/cn";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-[46px] w-full rounded-[13px] border border-input/80 bg-card/80 px-4 text-[15px] font-semibold text-foreground shadow-[0_10px_24px_rgba(15,23,42,0.07)] outline-none transition placeholder:text-muted-foreground focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 dark:bg-white/[0.055]",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";