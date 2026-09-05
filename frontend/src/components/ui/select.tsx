import { ChevronDown } from "lucide-react";
import { cn } from "@/utils/cn";
import { useState } from "react";

interface SelectFieldProps {
  value: string;
  onChange: (value: string) => void;
  options: string[];
  className?: string;
}

export function SelectField({ value, onChange, options, className }: SelectFieldProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "flex h-[46px] w-full items-center justify-between rounded-[7px] border border-input bg-card px-4 text-left text-[17px] font-medium shadow-input",
          className,
        )}
      >
        <span>{value}</span>
        <ChevronDown className="h-5 w-5 text-muted-foreground" />
      </button>
      {isOpen && (
        <div className="absolute top-[52px] z-50 w-full rounded-[7px] border border-input bg-card shadow-lg">
          {options.map((option) => (
            <button
              key={option}
              type="button"
              className="block w-full px-4 py-2 text-left hover:bg-muted"
              onClick={() => {
                onChange(option);
                setIsOpen(false);
              }}
            >
              {option}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
