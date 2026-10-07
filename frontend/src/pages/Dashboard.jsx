import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../api/client";
import {
  User,
  ShieldCheck,
  History,
  FileUp,
  FileDown,
  Award,
  KeyRound,
  CheckCircle,
  Clock,
  Lock,
} from "lucide-react";

export default function Dashboard() {
  const { user } = useAuth();
  const [activity, setActivity] = useState([]);
  const [loadingActivity, setLoadingActivity] = useState(true);

  useEffect(() => {
    let isMounted = true;
    (async () => {
      try {
        const res = await api.get("/auth/activity");
        if (isMounted) {
          setActivity(res.data?.activity || []);
        }
      } catch {
        // Failed activity fetch
      } finally {
        if (isMounted) {
          setLoadingActivity(false);
        }
      }
    })();
    return () => {
      isMounted = false;
    };
  }, []);

  const formatAction = (action) => {
    switch (action) {
      case "register":
        return "Account Registered";
      case "login":
        return "Successful Sign In";
      case "login_failed":
        return "Failed Sign In Attempt";
      case "login_locked":
        return "Account Locked Out";
      case "logout":
        return "Signed Out";
      default:
        return action;
    }
  };

  const formatTimestamp = (isoStr) => {
    try {
      const date = new Date(isoStr);
      return date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
    } catch {
      return isoStr;
    }
  };

  return (
    <div className="flex-1 py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      {/* Welcome Banner */}
      <div className="mb-8">
        <p className="eyebrow text-lime-dark mb-1">AUTHENTICATED WORKSPACE</p>
        <h1 className="text-3xl font-extrabold text-ink tracking-tight flex items-center gap-2">
          Welcome back, {user?.name || "User"}
        </h1>
        <p className="text-sm text-ink-muted mt-1">
          Your CipherLock session is active with verified scrypt credentials.
        </p>
      </div>

      {/* Grid: Account, Security, Activity */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
        {/* Card 1: Account Profile */}
        <div className="bg-white rounded-xl border border-line p-6 shadow-card flex flex-col">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2.5 rounded-lg bg-navy text-lime">
              <User className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-ink">Account Profile</h2>
              <p className="text-xs text-ink-muted">Identity and privilege</p>
            </div>
          </div>
          <div className="space-y-3 flex-1 text-sm">
            <div>
              <span className="text-xs font-mono uppercase text-ink-muted block">Full Name</span>
              <span className="font-semibold text-ink">{user?.name}</span>
            </div>
            <div>
              <span className="text-xs font-mono uppercase text-ink-muted block">Email Address</span>
              <span className="font-mono text-xs text-ink">{user?.email}</span>
            </div>
            <div className="flex items-center justify-between pt-2 border-t border-line">
              <div>
                <span className="text-xs font-mono uppercase text-ink-muted block">Role</span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-800">
                  {user?.is_admin ? "Administrator" : "Standard User"}
                </span>
              </div>
              <div className="text-right">
                <span className="text-xs font-mono uppercase text-ink-muted block">Status</span>
                <span className="inline-flex items-center space-x-1 text-xs font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                  <CheckCircle className="w-3 h-3 text-emerald-600" />
                  <span>Active</span>
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Card 2: Security Status */}
        <div className="bg-white rounded-xl border border-line p-6 shadow-card flex flex-col">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2.5 rounded-lg bg-navy text-lime">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-ink">Active Security</h2>
              <p className="text-xs text-ink-muted">Guarantees in Phase 2</p>
            </div>
          </div>
          <ul className="space-y-2.5 flex-1 text-xs text-ink">
            <li className="flex items-start space-x-2">
              <CheckCircle className="w-4 h-4 text-lime-dark flex-shrink-0 mt-0.5" />
              <span>
                <strong>Password Protection:</strong> Salted scrypt key derivation (DoS-capped at 128 chars).
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle className="w-4 h-4 text-lime-dark flex-shrink-0 mt-0.5" />
              <span>
                <strong>Session Security:</strong> Signed cookies, SameSite=Lax, 30-min idle timeout.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle className="w-4 h-4 text-lime-dark flex-shrink-0 mt-0.5" />
              <span>
                <strong>CSRF Guard:</strong> Synchronizer token pattern enforced on all state modifications.
              </span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle className="w-4 h-4 text-lime-dark flex-shrink-0 mt-0.5" />
              <span>
                <strong>Brute-Force Lockout:</strong> 5 failed attempts per (email, IP) triggers 300s lock.
              </span>
            </li>
          </ul>
        </div>

        {/* Card 3: Recent Activity */}
        <div className="bg-white rounded-xl border border-line p-6 shadow-card flex flex-col">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2.5 rounded-lg bg-navy text-lime">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-ink">Recent Activity</h2>
              <p className="text-xs text-ink-muted">Security audit events</p>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto max-h-48 text-xs">
            {loadingActivity ? (
              <p className="text-ink-muted italic py-4 text-center">Loading audit events...</p>
            ) : activity.length === 0 ? (
              <p className="text-ink-muted italic py-4 text-center">No recent activity recorded.</p>
            ) : (
              <ul className="space-y-2 divide-y divide-line/60">
                {activity.map((item, idx) => (
                  <li key={idx} className="pt-2 first:pt-0">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-ink">{formatAction(item.action)}</span>
                      <span className="text-[10px] text-ink-muted font-mono">
                        {formatTimestamp(item.created_at)}
                      </span>
                    </div>
                    {item.detail && (
                      <span className="text-[11px] text-ink-muted font-mono">{item.detail}</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      {/* Feature Tiles (Planned for Later Phases) */}
      <div className="border-t border-line pt-8">
        <div className="mb-4">
          <p className="eyebrow text-ink-muted">CRYPTOGRAPHIC MODULES</p>
          <h2 className="text-xl font-bold text-ink">Upcoming Features</h2>
          <p className="text-xs text-ink-muted">
            These components are scheduled for subsequent project implementation phases.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Send File */}
          <div className="bg-slate-50 border border-dashed border-line rounded-xl p-5 opacity-75 relative">
            <div className="flex justify-between items-start mb-3">
              <div className="p-2 rounded-lg bg-slate-200 text-slate-600">
                <FileUp className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono font-semibold bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full">
                Phase 5
              </span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">Send Encrypted File</h3>
            <p className="text-xs text-ink-muted mb-3">
              Hybrid AES-256-GCM + RSA encryption with digital signature.
            </p>
            <span className="text-[11px] font-mono text-slate-500 font-medium">
              Available in Phase 5
            </span>
          </div>

          {/* Received Files */}
          <div className="bg-slate-50 border border-dashed border-line rounded-xl p-5 opacity-75 relative">
            <div className="flex justify-between items-start mb-3">
              <div className="p-2 rounded-lg bg-slate-200 text-slate-600">
                <FileDown className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono font-semibold bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full">
                Phase 6
              </span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">Received Files</h3>
            <p className="text-xs text-ink-muted mb-3">
              Recipient verification, integrity checking, and safe download.
            </p>
            <span className="text-[11px] font-mono text-slate-500 font-medium">
              Available in Phase 6
            </span>
          </div>

          {/* Certificates */}
          <div className="bg-slate-50 border border-dashed border-line rounded-xl p-5 opacity-75 relative">
            <div className="flex justify-between items-start mb-3">
              <div className="p-2 rounded-lg bg-slate-200 text-slate-600">
                <Award className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono font-semibold bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full">
                Phase 4
              </span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">X.509 Certificate</h3>
            <p className="text-xs text-ink-muted mb-3">
              Mini Certificate Authority issuance and validity verification.
            </p>
            <span className="text-[11px] font-mono text-slate-500 font-medium">
              Available in Phase 4
            </span>
          </div>

          {/* Cryptographic Keys */}
          <div className="bg-slate-50 border border-dashed border-line rounded-xl p-5 opacity-75 relative">
            <div className="flex justify-between items-start mb-3">
              <div className="p-2 rounded-lg bg-slate-200 text-slate-600">
                <KeyRound className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono font-semibold bg-slate-200 text-slate-700 px-2 py-0.5 rounded-full">
                Phase 3
              </span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">RSA Key Pair</h3>
            <p className="text-xs text-ink-muted mb-3">
              RSA-3072 key generation and encrypted PKCS#8 storage.
            </p>
            <span className="text-[11px] font-mono text-slate-500 font-medium">
              Available in Phase 3
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
