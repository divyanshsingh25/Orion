import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ChartDatum, SeverityName } from "@/types/dashboard";
import { cn } from "@/utils/cn";
import { ChartTooltip } from "@/charts/ChartTooltip";

const dotClass: Record<string, string> = {
  Critical: "bg-red-500 text-red-500",
  High: "bg-orange-500 text-orange-500",
  Medium: "bg-amber-500 text-amber-500",
  Low: "bg-sky-400 text-sky-400",
};

const gradientIds: Record<string, string> = {
  Critical: "severityCritical",
  High: "severityHigh",
  Medium: "severityMedium",
  Low: "severityLow",
};

export function SeverityBarChart({
  data,
  onBarClick,
}: {
  data: ChartDatum[];
  onBarClick?: (severity: SeverityName) => void;
}) {
  return (
    <div className="mt-4">
      <div className="h-[380px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 6, right: 8, bottom: 8, left: 2 }} barCategoryGap={38}>
            <defs>
              <linearGradient id="severityCritical" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb7185" /><stop offset="100%" stopColor="#dc2626" /></linearGradient>
              <linearGradient id="severityHigh" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb923c" /><stop offset="100%" stopColor="#ea580c" /></linearGradient>
              <linearGradient id="severityMedium" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fbbf24" /><stop offset="100%" stopColor="#d97706" /></linearGradient>
              <linearGradient id="severityLow" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" /><stop offset="100%" stopColor="#2563eb" /></linearGradient>
            </defs>
            <CartesianGrid className="chart-grid" vertical={false} stroke="currentColor" opacity={0.13} />
            <XAxis dataKey="name" axisLine={false} tickLine={false} interval={0} tick={{ fill: "#64748b", fontSize: 13, fontWeight: 700 }} />
            <YAxis axisLine={false} tickLine={false} domain={[0, 'auto']} tick={{ fill: "#64748b", fontSize: 12, fontWeight: 700 }} />
            <Tooltip cursor={{ fill: "rgba(14,165,233,0.08)" }} content={<ChartTooltip />} />
            <Bar 
              dataKey="value" 
              radius={[12, 12, 5, 5]} 
              barSize={34} 
              isAnimationActive 
              animationDuration={950}
              onClick={(entry: any) => {
                if (entry && entry.name && onBarClick) {
                  onBarClick(entry.name as SeverityName);
                }
              }}
              className={onBarClick ? "cursor-pointer" : undefined}
            >
              {data.map((entry) => (
                <Cell 
                  key={entry.name} 
                  fill={`url(#${gradientIds[entry.name]})`}
                  className={onBarClick ? "cursor-pointer hover:opacity-80 transition-opacity" : undefined} 
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-7 gap-y-2 text-[14px] font-bold text-muted-foreground">
        {data.map((item) => (
          <div 
            key={item.name} 
            onClick={() => onBarClick && onBarClick(item.name as SeverityName)}
            className={cn(
              "flex items-center gap-2",
              onBarClick && "cursor-pointer hover:opacity-80 transition-opacity"
            )}
            title={onBarClick ? `View ${item.name} findings` : undefined}
          >
            <span className={cn("h-2.5 w-2.5 rounded-full", dotClass[item.name])} />
            <span>{item.name}</span>
            <span className={cn("font-bold", dotClass[item.name])}>{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}