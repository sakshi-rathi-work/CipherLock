import React from "react";
import { ShieldCheck } from "lucide-react";

export default function Footer() {
  return (
    <footer className="bg-navy-deep text-slate-400 py-6 text-xs border-t border-white/10 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-3 text-center md:text-left">
        <div className="flex items-center gap-2">
          <span
            className="w-5 h-5 rounded-md inline-flex items-center justify-center font-extrabold text-[10px] text-navy"
            style={{ background: "linear-gradient(145deg,#d4f98c,#a6d94a)" }}
          >
            C
          </span>
          <span>© 2026 CipherLock</span>
        </div>
        <span className="inline-flex items-center gap-1.5 text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-lime" aria-hidden="true" />
          AES-256-GCM · RSA-OAEP · RSA-PSS · X.509
        </span>
      </div>
    </footer>
  );
}
