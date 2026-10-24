// Monospace security status terminal box (Phase 8).
import React from "react";
import { Terminal } from "lucide-react";

export default function SecurityBox({ text }) {
  return (
    <div className="card p-4 bg-navy-950 border border-navy-700 shadow-md">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-navy-800">
        <div className="flex items-center gap-2 text-xs font-mono text-lime uppercase tracking-wider">
          <Terminal className="w-4 h-4 text-lime" aria-hidden="true" />
          <span>CipherLock Security Audit Terminal</span>
        </div>
        <span className="text-xs font-mono text-slate-500">crypto/package.py</span>
      </div>
      <pre className="font-mono text-lime text-xs sm:text-sm whitespace-pre overflow-x-auto p-3 rounded bg-black/60 border border-navy-800/80 selection:bg-lime selection:text-navy-950">
        {text}
      </pre>
    </div>
  );
}
