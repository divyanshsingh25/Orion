import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartTooltip } from "@/charts/ChartTooltip";

interface ActivityDatum {
  day: string;
  Critical: number;
  High: number;
  Medium: number;
}

export function ActivityTrendChart({ data }: { data: ActivityDatum[] }) {
  return (
    <div className="h-[280px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="criticalArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} /><stop offset="100%" stopColor="#ef4444" stopOpacity={0.02} /></linearGradient>
            <linearGradient id="highArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f97316" stopOpacity={0.28} /><stop offset="100%" stopColor="#f97316" stopOpacity={0.02} /></linearGradient>
            <linearGradient id="mediumArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f59e0b" stopOpacity={0.25} /><stop offset="100%" stopColor="#f59e0b" stopOpacity={0.03} /></linearGradient>
          </defs>
          <CartesianGrid className="chart-grid" stroke="currentColor" opacity={0.13} />
          <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 12, fontWeight: 700 }} />
          <YAxis axisLine={false} tickLine={false} ticks={[0, 6, 12, 18, 24]} tick={{ fill: "#64748b", fontSize: 12, fontWeight: 700 }} />
          <Tooltip content={<ChartTooltip />} />
          <Area type="monotone" dataKey="Medium" stroke="#f59e0b" fill="url(#mediumArea)" strokeWidth={3} dot={false} isAnimationActive />
          <Area type="monotone" dataKey="High" stroke="#f97316" fill="url(#highArea)" strokeWidth={3} dot={false} isAnimationActive />
          <Area type="monotone" dataKey="Critical" stroke="#ef4444" fill="url(#criticalArea)" strokeWidth={3} dot={false} isAnimationActive />
          <Legend verticalAlign="bottom" height={30} iconType="circle" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}