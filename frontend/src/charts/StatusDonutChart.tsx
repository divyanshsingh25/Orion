import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { ChartDatum } from "@/types/dashboard";
import { cn } from "@/utils/cn";
import { ChartTooltip } from "@/charts/ChartTooltip";

const statusColors: Record<string, { bg: string; fill: string }> = {
  Complete: { bg: "bg-emerald-500", fill: "#10b981" },
  Completed: { bg: "bg-emerald-500", fill: "#10b981" },
  Scanning: { bg: "bg-cyan-500", fill: "#06b6d4" },
  Running: { bg: "bg-cyan-500", fill: "#06b6d4" },
  Queued: { bg: "bg-blue-500", fill: "#3b82f6" },
  Failed: { bg: "bg-red-500", fill: "#ef4444" },
  Cancelled: { bg: "bg-amber-500", fill: "#f59e0b" },
};

export function StatusDonutChart({ data }: { data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + (item.value || 0), 0);
  const chartData = data.filter((d) => (d.value || 0) > 0);

  return (
    <div className="mt-4 grid grid-cols-[190px_1fr] items-center gap-5">
      <div className="h-[185px] w-[185px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip content={<ChartTooltip />} />
            <Pie
              data={chartData.length > 0 ? chartData : [{ name: "No Scans", value: 1, color: "rgba(148,163,184,0.2)" }]}
              dataKey="value"
              innerRadius={52}
              outerRadius={82}
              paddingAngle={chartData.length > 1 ? 3 : 0}
              cornerRadius={8}
              stroke="none"
              isAnimationActive
              animationDuration={800}
            >
              {chartData.length > 0 ? (
                chartData.map((entry, index) => (
                  <Cell
                    key={`status-cell-${index}`}
                    fill={entry.color || statusColors[entry.name]?.fill || "#06b6d4"}
                  />
                ))
              ) : (
                <Cell fill="rgba(148,163,184,0.2)" />
              )}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="space-y-3.5 text-[15px] font-semibold text-muted-foreground">
        {data.map((item) => {
          const colorInfo = statusColors[item.name] || { bg: "bg-cyan-500", fill: item.color || "#06b6d4" };
          return (
            <div key={item.name} className="grid grid-cols-[1fr_auto] items-center gap-3">
              <div className="flex items-center gap-2.5">
                <span
                  className={cn("h-3 w-3 rounded-full shrink-0 shadow-sm", colorInfo.bg)}
                  style={{ backgroundColor: item.color || colorInfo.fill }}
                />
                <span className="text-foreground/90 font-medium">{item.name}</span>
              </div>
              <strong className="font-mono text-foreground font-bold">{item.value || 0}</strong>
            </div>
          );
        })}
        <div className="grid grid-cols-[1fr_auto] border-t border-border/70 pt-2.5 text-foreground">
          <span className="text-muted-foreground font-semibold">Total</span>
          <strong className="font-mono text-foreground font-bold">{total}</strong>
        </div>
      </div>
    </div>
  );
}