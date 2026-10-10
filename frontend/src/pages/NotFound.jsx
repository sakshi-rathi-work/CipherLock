import React from "react";
import { Link } from "react-router-dom";
import { Compass } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center py-20 px-4 text-center animate-fade-up">
      <div className="relative mb-6">
        <span className="absolute inset-0 blur-2xl bg-lime/40 rounded-full" aria-hidden="true" />
        <span className="icon-tile w-16 h-16 relative"><Compass className="w-8 h-8" /></span>
      </div>
      <p className="eyebrow text-lime-dark mb-2">404 error</p>
      <h1 className="text-4xl font-extrabold text-ink tracking-tight mb-3">Page not found</h1>
      <p className="text-sm text-ink-muted max-w-sm mb-8">
        The requested URL was not found in the CipherLock client application.
      </p>
      <Link to="/dashboard" className="btn-lime px-6 py-3 rounded-lg text-sm">
        Return to Dashboard
      </Link>
    </div>
  );
}
