import React from "react";
import { Lock, ShieldCheck, KeyRound, FileCheck2 } from "lucide-react";

const POINTS = [
  { icon: Lock, title: "End-to-end protection", text: "Files are sealed with AES-256-GCM before they touch the disk." },
  { icon: KeyRound, title: "Recipient-only access", text: "Session keys are wrapped with the recipient's RSA public key." },
  { icon: FileCheck2, title: "Verifiable senders", text: "RSA-PSS signatures and X.509 certificates prove who sent what." },
];

/**
 * Shared split-screen layout for the Login and Register pages.
 * Left: brand / trust panel (desktop only). Right: the form content.
 */
export default function AuthShell({ children }) {
  return (
    <div className="flex-1 grid lg:grid-cols-[1.05fr_1fr]">
      {/* Brand panel */}
      <aside className="hidden lg:flex relative overflow-hidden text-white bg-navy">
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(700px 420px at 85% 0%, rgba(196,241,110,0.20), transparent 60%), radial-gradient(600px 500px at 0% 100%, rgba(60,120,190,0.30), transparent 60%), linear-gradient(160deg,#10294a 0%,#0b1b2e 55%,#07121f 100%)",
          }}
        />
        <div className="absolute inset-0 bg-grid opacity-70" />
        <div className="relative z-10 flex flex-col justify-between p-12 xl:p-16 w-full max-w-xl ml-auto">
          <div>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-3 py-1 eyebrow text-lime">
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" /> Secure file sharing
            </span>
            <h2 className="mt-6 text-4xl xl:text-[2.6rem] font-extrabold tracking-tight leading-[1.1]">
              Privacy that travels
              <br />
              with <span className="text-lime">every file.</span>
            </h2>
            <p className="mt-4 text-slate-300 leading-relaxed max-w-md">
              CipherLock combines hybrid encryption, digital signatures and a mini certificate
              authority so only the intended recipient can read what you send.
            </p>
          </div>

          <ul className="mt-10 space-y-5">
            {POINTS.map(({ icon: Icon, title, text }) => (
              <li key={title} className="flex gap-4">
                <span className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-lime inline-flex items-center justify-center flex-shrink-0">
                  <Icon className="w-5 h-5" aria-hidden="true" />
                </span>
                <div>
                  <p className="font-semibold text-sm">{title}</p>
                  <p className="text-sm text-slate-400 mt-0.5">{text}</p>
                </div>
              </li>
            ))}
          </ul>

          <p className="mt-10 text-xs font-mono text-slate-500">AES-256-GCM · RSA-3072 · SHA-256 · scrypt</p>
        </div>
      </aside>

      {/* Form column */}
      <div className="flex items-center justify-center py-12 px-4 sm:px-8">
        <div className="w-full max-w-md animate-fade-up">{children}</div>
      </div>
    </div>
  );
}
