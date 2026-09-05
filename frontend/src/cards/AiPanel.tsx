import { useEffect, useState, useRef } from "react";
import { Bot, CheckCircle2, SendHorizonal, Sparkles, Pin, PinOff, Trash2 } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { MarkdownText } from "@/components/MarkdownText";
import type { AssistantMessage, Risk, Vulnerability } from "@/types/dashboard";
import { sendChatMessage } from "@/services/api";
import { cn } from "@/utils/cn";

const suggestions = ["Summarize top risks", "Draft remediation plan", "Explain CVSS drift", "Create exec brief"];

export function AiPanel({ risks, messages = [], defaultMessage, domains = [], vulnerabilities = [] }: { risks: Risk[]; messages?: AssistantMessage[]; defaultMessage?: string; domains?: string[]; vulnerabilities?: Vulnerability[] }) {
  const [draft, setDraft] = useState("");
  const [chat, setChat] = useState<AssistantMessage[]>([]);
  const [isPinned, setIsPinned] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const lastProcessedDefaultMessageRef = useRef<string | null>(null);

  // Auto-scroll to bottom on chat update or loading state change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [chat, isLoading]);

  // Auto-send default message when received (e.g. from "Ask Orion AI" on vulnerability click)
  useEffect(() => {
    if (defaultMessage && lastProcessedDefaultMessageRef.current !== defaultMessage) {
      lastProcessedDefaultMessageRef.current = defaultMessage;

      const userMsg: AssistantMessage = { role: "user", content: defaultMessage };
      const newChat: AssistantMessage[] = [...chat, userMsg];
      setChat(newChat);
      setIsLoading(true);

      sendChatMessage(newChat)
        .then((response) => {
          setChat([...newChat, response]);
        })
        .catch(() => {
          setChat([
            ...newChat,
            {
              role: "assistant",
              content: "**Error:** Failed to connect to Orion AI backend. Ensure your API key is configured.",
            },
          ]);
        })
        .finally(() => {
          setIsLoading(false);
        });
    }
  }, [defaultMessage]);

  async function sendMessage(text = draft) {
    if (!text.trim() || isLoading) return;
    setDraft("");
    
    const newChat: AssistantMessage[] = [...chat, { role: "user", content: text }];
    setChat(newChat);
    setIsLoading(true);

    try {
      const response = await sendChatMessage(newChat);
      setChat([...newChat, response]);
    } catch (error) {
      setChat([...newChat, { role: "assistant", content: "**Error:** Failed to connect to Orion AI backend. Ensure your API key is configured." }]);
    } finally {
      setIsLoading(false);
    }
  }

  async function handleDomainSelect(e: React.ChangeEvent<HTMLSelectElement>) {
    const domain = e.target.value;
    if (!domain || isLoading) return;
    e.target.value = "";
    
    const domainVulns = vulnerabilities.filter(v => v.asset.includes(domain) || domain.includes(v.asset));
    let contextStr = `Context for the domain ${domain}:\n`;
    if (domainVulns.length === 0) {
      contextStr += "No open vulnerabilities found for this domain.\n";
    } else {
      domainVulns.forEach(v => {
        contextStr += `- Title: ${v.title} (Severity: ${v.severity})\n`;
        contextStr += `  Asset: ${v.asset}\n`;
        contextStr += `  CVSS: ${v.cvss}, OWASP: ${v.owasp}\n`;
        contextStr += `  Evidence: ${v.evidence}\n`;
      });
    }

    const systemMessage: AssistantMessage = { role: "system", content: contextStr };
    const userMessage: AssistantMessage = { role: "user", content: `Analyze all findings for the domain: ${domain} and provide real-time analysis and remediation steps.` };
    
    const newChat: AssistantMessage[] = [...chat, systemMessage, userMessage];
    setChat(newChat);
    setIsLoading(true);

    try {
      const response = await sendChatMessage(newChat);
      setChat([...newChat, response]);
    } catch (error) {
      setChat([...newChat, { role: "assistant", content: "**Error:** Failed to connect to Orion AI backend. Ensure your API key is configured." }]);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <aside data-pet-obstacle="true" className={cn(
      "panel flex max-h-[calc(100vh-120px)] min-h-[620px] flex-col overflow-hidden transition-all duration-300",
      isPinned ? "fixed bottom-6 right-6 z-50 w-[380px] shadow-2xl border-cyan-500/50" : "sticky top-[100px]"
    )}>
      <div className="flex h-[56px] shrink-0 items-center justify-between border-b border-border/70 px-4">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan-500 text-white shadow-sm">
            <Sparkles className="h-4 w-4" />
          </div>
          <span className="text-[16px] font-bold text-foreground whitespace-nowrap">Orion AI</span>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {domains.length > 0 && (
            <select 
              onChange={handleDomainSelect} 
              defaultValue=""
              className="h-7 cursor-pointer rounded-lg border border-border/80 bg-muted/50 px-2 text-[12px] font-medium text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus:border-cyan-400 transition max-w-[120px]"
            >
              <option value="" disabled hidden>Ask Target...</option>
              {domains.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
          )}
          <button 
            onClick={() => setChat([])} 
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-500"
            title="Clear chat"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
          <button 
            onClick={() => setIsPinned(!isPinned)} 
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-cyan-400"
            title={isPinned ? "Unpin panel" : "Pin panel to screen"}
          >
            {isPinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col overflow-hidden">


        <div ref={scrollRef} className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
          {chat.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center text-muted-foreground space-y-3 pb-8">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-500">
                <Sparkles className="h-6 w-6" />
              </div>
              <p className="text-[15px] font-medium text-foreground/80">How can I help you today?</p>
              <p className="max-w-[280px] text-[13px]">Select a target domain to analyze its findings, or ask me a security question to get started.</p>
            </div>
          ) : (
            <>
              {chat.filter(m => m.role !== "system").map((message, index) => (
                <motion.div
                  key={`${message.role}-${index}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn("flex", message.role === "user" ? "justify-end" : "justify-start")}
                >
                  <div className={cn("max-w-[88%] rounded-[16px] px-4 py-3 text-[14px] shadow-sm", message.role === "user" ? "bg-gradient-to-r from-blue-600 to-cyan-500 text-white" : "border border-border/70 bg-background/70 text-foreground")}> 
                    <MarkdownText content={message.content} />
                  </div>
                </motion.div>
              ))}
              {isLoading && (
                <div className="flex justify-start">
                  <div className="flex items-center gap-1.5 rounded-full border border-border/70 bg-background/70 px-4 py-3">
                    <span className="typing-dot h-2 w-2 rounded-full bg-cyan-400" />
                    <span className="typing-dot h-2 w-2 rounded-full bg-cyan-400" />
                    <span className="typing-dot h-2 w-2 rounded-full bg-cyan-400" />
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      <div className="border-t border-border/70 px-4 py-4">
        <div className="mb-3 flex gap-2 overflow-hidden">
          {suggestions.map((item) => (
            <button key={item} type="button" onClick={() => sendMessage(item)} className="shrink-0 rounded-full border border-border/70 bg-card/70 px-3 py-1.5 text-[12px] font-bold text-muted-foreground transition hover:border-cyan-300 hover:text-cyan-500">
              {item}
            </button>
          ))}
        </div>
        <div className="relative flex items-end gap-2 bg-card/80 rounded-[20px] border border-input/80 focus-within:border-cyan-400 focus-within:ring-1 focus-within:ring-cyan-400/50 p-1.5">
          <textarea 
            value={draft} 
            onChange={(event) => setDraft(event.target.value)} 
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
            className="max-h-[150px] min-h-[44px] w-full resize-none bg-transparent px-3 py-3 text-[14px] outline-none placeholder:text-muted-foreground" 
            placeholder="Message Orion AI..." 
            rows={1}
          />
          <Button size="icon" className="h-10 w-10 shrink-0 rounded-[14px]" onClick={() => sendMessage()}>
            <SendHorizonal className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </aside>
  );
}