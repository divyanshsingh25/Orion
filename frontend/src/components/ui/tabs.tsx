import { cn } from "@/utils/cn";

interface FilterTabsProps {
  tabs: string[];
  active: string;
  onChange: (tab: string) => void;
}

export function FilterTabs({ tabs, active, onChange }: FilterTabsProps) {
  return (
    <div className="flex h-[45px] rounded-[8px] bg-slate-100 p-1 dark:bg-slate-900">
      {tabs.map((tab) => (
        <button
          key={tab}
          type="button"
          onClick={() => onChange(tab)}
          className={cn(
            "h-[37px] flex-1 rounded-[7px] text-[17px] font-semibold text-muted-foreground transition",
            active === tab && "bg-card text-foreground shadow-input",
          )}
        >
          {tab}
        </button>
      ))}
    </div>
  );
}
