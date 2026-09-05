import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { SeverityName } from "@/types/dashboard";

interface CvssDatum {
  range: string;
  value: number;
  color: string;
}

export function CvssChart({
  data,
  onBarClick,
}: {
  data: CvssDatum[];
  onBarClick?: (severity: SeverityName) => void;
}) {
  return (
    <div className="h-[250px] w-full py-2">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 20, right: 10, left: -20, bottom: 0 }} barCategoryGap={16}>
          <defs>
            <linearGradient id="cvssBlue" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" /><stop offset="100%" stopColor="#0ea5e9" /></linearGradient>
            <linearGradient id="cvssIndigo" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#818cf8" /><stop offset="100%" stopColor="#4f46e5" /></linearGradient>
            <linearGradient id="cvssAmber" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fbbf24" /><stop offset="100%" stopColor="#f59e0b" /></linearGradient>
            <linearGradient id="cvssOrange" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb923c" /><stop offset="100%" stopColor="#f97316" /></linearGradient>
            <linearGradient id="cvssRed" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb7185" /><stop offset="100%" stopColor="#e11d48" /></linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="#334155" opacity={0.2} strokeDasharray="3 3" />
          <XAxis 
            dataKey="range" 
            axisLine={false} 
            tickLine={false} 
            interval={0}
            tick={{ fill: "#94a3b8", fontSize: 11, fontWeight: 600 }}
            dy={8}
          />
          <YAxis 
            axisLine={false} 
            tickLine={false} 
            allowDecimals={false}
            tick={{ fill: "#94a3b8", fontSize: 11, fontWeight: 500 }}
            dx={-4}
          />
          <Tooltip 
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload as CvssDatum;
                return (
                  <div className="rounded-[12px] border border-border/70 bg-card/95 px-3.5 py-2.5 text-[12px] font-bold shadow-[0_18px_42px_rgba(15,23,42,0.22)] backdrop-blur-xl">
                    <div className="mb-1 text-muted-foreground">{item.range}</div>
                    <div className="flex items-center justify-between gap-4">
                      <span style={{ color: item.color }}>Findings</span>
                      <span className="text-foreground font-mono">{item.value}</span>
                    </div>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar 
            dataKey="value" 
            radius={[6, 6, 0, 0]} 
            maxBarSize={44} 
            isAnimationActive 
            animationDuration={800}
            animationEasing="ease-out"
            onClick={(entry: any) => {
              if (entry && entry.range && onBarClick) {
                const sevName = entry.range.split(" ")[0] as SeverityName;
                onBarClick(sevName);
              }
            }}
            className={onBarClick ? "cursor-pointer" : undefined}
          >
            {data.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.color || "#06b6d4"} 
                className={onBarClick ? "cursor-pointer hover:opacity-80 transition-opacity" : undefined}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}