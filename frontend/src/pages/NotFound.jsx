import React from "react";
import { Link } from "react-router-dom";
import { AlertTriangle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center py-16 px-4 text-center">
      <div className="p-3 bg-amber-50 text-amber-700 rounded-xl mb-4 border border-amber-200">
        <AlertTriangle className="w-8 h-8" />
      </div>
      <p className="eyebrow text-ink-muted mb-1">404 ERROR</p>
      <h1 className="text-3xl font-extrabold text-ink tracking-tight mb-2">
        Page Not Found
      </h1>
      <p className="text-sm text-ink-muted max-w-sm mb-6">
        The requested URL was not found in the CipherLock client application.
      </p>
      <Link
        to="/dashboard"
        className="btn-lime px-4 py-2 rounded-lg text-sm font-semibold inline-flex items-center space-x-1"
      >
        <span>Return to Dashboard</span>
      </Link>
    </div>
  );
}
