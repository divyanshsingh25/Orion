import type { ReactNode } from "react";

function renderInline(text: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={index} className="font-bold text-foreground">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={index} className="rounded-md bg-slate-950/[0.08] px-1.5 py-0.5 font-mono text-[0.92em] text-cyan-600 dark:bg-white/10 dark:text-cyan-300">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

export function MarkdownText({ content }: { content: string }) {
  const lines = content.split("\n");
  const listLines = lines.filter((line) => line.trim().startsWith("- "));
  const normalLines = lines.filter((line) => !line.trim().startsWith("- "));

  return (
    <div className="space-y-2 text-[14px] leading-[1.55]">
      {normalLines.map((line, index) => line ? <p key={index}>{renderInline(line)}</p> : null)}
      {listLines.length > 0 && (
        <ul className="space-y-1 pl-1">
          {listLines.map((line) => (
            <li key={line} className="flex gap-2">
              <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
              <span>{renderInline(line.replace(/^\s*-\s*/, ""))}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}