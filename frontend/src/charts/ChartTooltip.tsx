interface TooltipPayloadItem {
  name?: string;
  value?: number;
  color?: string;
  payload?: Record<string, unknown>;
}

interface ChartTooltipProps {
  active?: boolean;
  label?: string;
  payload?: TooltipPayloadItem[];
}

export function ChartTooltip({ active, label, payload }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;

  return (
    <div className="rounded-[12px] border border-border/70 bg-card/95 px-3 py-2 text-[12px] font-bold shadow-[0_18px_42px_rgba(15,23,42,0.18)] backdrop-blur-xl">
      {label ? <div className="mb-1 text-muted-foreground">{label}</div> : null}
      <div className="space-y-1">
        {payload.map((item) => (
          <div key={`${item.name}-${item.value}`} className="flex items-center justify-between gap-4">
            <span>{item.name}</span>
            <span className="text-cyan-500">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}