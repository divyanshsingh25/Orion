import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { ChartDatum } from "@/types/dashboard";
import { ChartTooltip } from "@/charts/ChartTooltip";

const fallbackColors = ["#38bdf8", "#34d399", "#fbbf24", "#a855f7", "#f43f5e", "#fb923c"];

export function AttackVectorChart({ data }: { data: ChartDatum[] }) {
  const chartData = data.filter((d) => (d.value || 0) > 0);
  const total = chartData.reduce((sum, item) => sum + (item.value || 0), 0);

  return (
    <div className="mt-2 space-y-4">
      <div className="mx-auto h-[200px] w-[240px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip content={<ChartTooltip />} />
            <Pie
              data={chartData.length > 0 ? chartData : [{ name: "No Vectors", value: 1, color: "rgba(148,163,184,0.2)" }]}
              dataKey="value"
              innerRadius={48}
              outerRadius={88}
              paddingAngle={chartData.length > 1 ? 3 : 0}
              cornerRadius={6}
              stroke="hsl(var(--card))"
              strokeWidth={3}
              isAnimationActive
              animationDuration={800}
            >
              {chartData.length > 0 ? (
                chartData.map((entry, index) => (
                  <Cell
                    key={`vector-cell-${index}`}
                    fill={entry.color || fallbackColors[index % fallbackColors.length]}
                  />
                ))
              ) : (
                <Cell fill="rgba(148,163,184,0.2)" />
              )}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Legend with Color Boxes & Counts for each Attack Vector */}
      <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-2 px-2 text-[12px] font-semibold text-muted-foreground">
        {chartData.length > 0 ? (
          chartData.map((item, index) => {
            const color = item.color || fallbackColors[index % fallbackColors.length];
            return (
              <div
                key={item.name}
                className="flex items-center gap-2 rounded-lg border border-border/60 bg-muted/30 px-2.5 py-1 transition hover:border-border hover:bg-muted/50"
              >
                <span
                  className="h-3 w-3 rounded-[4px] shrink-0 shadow-sm"
                  style={{ backgroundColor: color }}
                />
                <span className="text-foreground font-medium truncate max-w-[150px]">{item.name}</span>
                <span className="font-mono font-bold text-foreground/90">
                  {item.value}
                </span>
              </div>
            );
          })
        ) : (
          <span className="text-muted-foreground text-[13px]">No open attack vectors for this target.</span>
        )}
      </div>
    </div>
  );
}