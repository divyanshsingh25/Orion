import { cn } from "@/utils/cn";

interface InfoTileProps {
  label: string;
  value: string;
  valueClassName?: string;
  onClick?: () => void;
  className?: string;
}

export function InfoTile({ label, value, valueClassName, onClick, className }: InfoTileProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        "thin-panel h-[74px] px-4 py-3 transition hover:-translate-y-0.5 hover:border-cyan-300/60",
        onClick && "cursor-pointer hover:border-cyan-400 hover:shadow-md hover:bg-cyan-500/[0.04]",
        className
      )}
    >
      <div className="section-label text-[10px]">{label}</div>
      <div className={cn("mt-2 truncate text-[15px] font-bold", valueClassName)}>{value}</div>
    </div>
  );
}