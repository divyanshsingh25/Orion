import { useQuery } from "@tanstack/react-query";
import { ArrowUpDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { getDashboardData } from "@/services/api";
import type { ScanHistoryRow } from "@/types/dashboard";

const statusTone = {
  Running: "running",
  Completed: "success",
  Failed: "failed",
  Cancelled: "failed",
} as const;

export function ScanHistoryPage() {
  const { data } = useQuery({ queryKey: ["scan-history"], queryFn: getDashboardData });
  const rows = (data?.scanHistory ?? []) as ScanHistoryRow[];

  return (
    <div>
      <h1 className="text-[37px] font-extrabold leading-none">Scan History</h1>
      <p className="muted-copy mt-5">Review past security assessments</p>

      <section className="panel mt-[33px] px-[30px] pb-[30px] pt-[29px]">
        <h2 className="text-[20px] font-extrabold">All Scans</h2>
        <p className="mt-2 text-[19px] font-medium text-muted-foreground">{rows.length} total scans</p>

        <div className="mt-8 overflow-hidden rounded-[7px] border border-border">
          <table className="w-full border-collapse text-left text-[17px]">
            <thead>
              <tr className="h-[49px] text-[16px] font-semibold text-muted-foreground">
                <th className="w-[310px] px-5 font-semibold"><span className="inline-flex items-center gap-4">Target <ArrowUpDown className="h-5 w-5" /></span></th>
                <th className="w-[200px] px-5 font-semibold">Status</th>
                <th className="w-[130px] px-5 font-semibold">Type</th>
                <th className="px-5 text-center font-semibold">Critical</th>
                <th className="px-5 text-center font-semibold">High</th>
                <th className="px-5 text-center font-semibold">Medium</th>
                <th className="px-5 text-center font-semibold">Low</th>
                <th className="w-[190px] px-5 font-semibold"><span className="inline-flex items-center gap-4">Started <ArrowUpDown className="h-5 w-5" /></span></th>
                <th className="w-[160px] px-5 font-semibold">Duration</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.target}-${index}`} className="h-[48px] border-t border-border text-[16px]">
                  <td className="px-3 font-mono text-[16px]">{row.target}</td>
                  <td className="px-5"><Badge tone={statusTone[row.status]}>{row.status}</Badge></td>
                  <td className="px-5 text-muted-foreground">{row.type}</td>
                  <td className="px-5 text-center font-mono">{row.critical}</td>
                  <td className="px-5 text-center font-mono">{row.high}</td>
                  <td className="px-5 text-center font-mono">{row.medium}</td>
                  <td className="px-5 text-center font-mono">{row.low}</td>
                  <td className="px-5 text-muted-foreground">{row.started}</td>
                  <td className="px-5 text-muted-foreground">{row.duration}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}