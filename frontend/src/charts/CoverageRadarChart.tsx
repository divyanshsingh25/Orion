import { PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";

interface CoverageDatum {
  domain: string;
  score: number;
}

export function CoverageRadarChart({ data }: { data: CoverageDatum[] }) {
  const chartData = data.map((d) => ({
    ...d,
    score: Math.max(5, Math.min(100, d.score || 0)),
  }));

  return (
    <div className="mx-auto h-[260px] max-w-[360px] pt-2">
      <ResponsiveContainer width="100%" height="100%">
        <RadarChart data={chartData} outerRadius={82}>
          <defs>
            <linearGradient id="radarFill" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.65} />
              <stop offset="100%" stopColor="#2563eb" stopOpacity={0.35} />
            </linearGradient>
          </defs>
          <PolarGrid stroke="#94a3b8" strokeOpacity={0.25} />
          <PolarAngleAxis
            dataKey="domain"
            tick={{ fill: "#64748b", fontSize: 11, fontWeight: 700 }}
          />
          <PolarRadiusAxis
            angle={30}
            domain={[0, 100]}
            tick={false}
            axisLine={false}
          />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload as CoverageDatum;
                return (
                  <div className="rounded-[12px] border border-border/70 bg-card/95 px-3.5 py-2 text-[12px] font-bold shadow-[0_18px_42px_rgba(15,23,42,0.22)] backdrop-blur-xl">
                    <div className="mb-0.5 text-muted-foreground font-mono">{item.domain}</div>
                    <div className="flex items-center justify-between gap-4">
                      <span className="text-cyan-500">Security Posture</span>
                      <span className="text-foreground font-mono">{item.score}%</span>
                    </div>
                  </div>
                );
              }
              return null;
            }}
          />
          <Radar
            dataKey="score"
            stroke="#06b6d4"
            fill="url(#radarFill)"
            fillOpacity={1}
            strokeWidth={2.5}
            isAnimationActive
            animationDuration={850}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}