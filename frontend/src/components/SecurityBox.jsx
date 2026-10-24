// Monospace security status terminal box (Phase 8).
import React from "react";
import { Terminal } from "lucide-react";

export default function SecurityBox({ text }) {
  return (
    <div className="surface overflow-hidden shadow-card border border-navy-border">
      <div className="bg-navy px-5 py-3.5 flex items-center justify-between border-b border-navy-border">
        <div className="flex items-center gap-2.5 text-xs font-mono font-bold text-lime uppercase tracking-wider">
          <Terminal className="w-4 h-4 text-lime" aria-hidden="true" />
          <span>CipherLock Security Audit Terminal</span>
        </div>
        <span className="text-[11px] font-mono text-slate-300 bg-navy-surface px-2.5 py-1 rounded border border-navy-border font-medium">
          crypto/package.py
        </span>
      </div>
      <div className="p-4 sm:p-5 bg-navy-deep">
        <pre className="font-mono text-lime text-xs sm:text-[13px] leading-relaxed whitespace-pre overflow-x-auto p-4 rounded-xl bg-black/60 border border-navy-border/80 selection:bg-lime selection:text-navy-deep shadow-inner">
          {text}
        </pre>
      </div>
    </div>
  );
}
