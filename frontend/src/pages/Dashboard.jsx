import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
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
  Lock,
  Send,
  ArrowUpRight,
  UploadCloud,
} from "lucide-react";

export default function Dashboard() {
  const { user } = useAuth();
  const [activity, setActivity] = useState([]);
  const [loadingActivity, setLoadingActivity] = useState(true);
  const [stats, setStats] = useState(null);

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
    // Real sent/received counters (not audited server-side).
    api
      .get("/files/stats")
      .then((res) => isMounted && setStats(res.data))
      .catch(() => {});
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
      case "file_upload":
        return "File Sent";
      case "file_upload_failed":
        return "File Send Failed";
      case "file_list_sent":
        return "Viewed Sent Files";
      case "file_list_received":
        return "Viewed Received Files";
      case "file_access_denied":
        return "Blocked File Access";
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

  const modules = [
    { to: "/send", icon: FileUp, title: "Send Encrypted File", text: "Hybrid AES-256-GCM + RSA encryption with a digital signature.", cta: "Send a file", badge: "LIVE" },
    { to: "/sent", icon: Send, title: "Sent Files", text: "Files you have shared and their delivery status.", cta: "View sent files", badge: stats ? `${stats.sent_count} SENT` : "LIVE" },
    { to: "/received", icon: FileDown, title: "Received Files", text: "Encrypted files other users have sent to you.", cta: "Open inbox", badge: stats ? `${stats.received_count} RECEIVED` : "LIVE" },
    { to: "/directory", icon: Award, title: "Certificate Directory", text: "Inspect trusted X.509 identities issued by the CipherLock Root CA.", cta: "Browse certificates", badge: "LIVE" },
  ];

  const guarantees = [
    ["Password Protection", "Salted scrypt key derivation (DoS-capped at 128 chars)."],
    ["Session Security", "Signed cookies, SameSite=Lax, 30-min idle timeout."],
    ["CSRF Guard", "Synchronizer token pattern on all state modifications."],
    ["Brute-Force Lockout", "5 failed attempts per (email, IP) triggers a 300s lock."],
  ];

  return (
    <div className="page max-w-7xl">
      {/* Welcome hero */}
      <section className="hero-surface p-7 sm:p-9 mb-8">
        <div className="absolute inset-0 bg-grid opacity-60 pointer-events-none" aria-hidden="true" />
        <div className="relative flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <p className="eyebrow text-lime mb-2">Authenticated workspace</p>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
              Welcome back, {user?.name || "User"}
            </h1>
            <p className="text-sm text-slate-300 mt-2 max-w-xl">
              Your CipherLock session is active and protected by verified scrypt credentials.
            </p>
            <div className="flex flex-wrap items-center gap-2 mt-4">
              <span className="pill border-white/15 bg-white/10 text-slate-100">
                {user?.is_admin ? "Administrator" : "Standard User"}
              </span>
              <span className="pill border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
                <CheckCircle className="w-3 h-3" aria-hidden="true" /> Active
              </span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row lg:flex-col xl:flex-row gap-3">
            <Link to="/send" className="btn-lime px-5 py-3 rounded-lg text-sm">
              <UploadCloud className="w-4 h-4" aria-hidden="true" /> Send a file
            </Link>
            <Link
              to="/received"
              className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg text-sm font-semibold text-white border border-white/20 bg-white/5 hover:bg-white/10 transition-colors"
            >
              <FileDown className="w-4 h-4" aria-hidden="true" /> Open inbox
            </Link>
          </div>
        </div>

        {/* Counters */}
        <dl className="relative grid grid-cols-2 sm:grid-cols-3 gap-3 mt-8">
          {[
            ["Files sent", stats ? stats.sent_count : "—"],
            ["Files received", stats ? stats.received_count : "—"],
            ["Key strength", "RSA-3072"],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl bg-white/5 border border-white/10 px-4 py-3 backdrop-blur-sm">
              <dt className="font-mono text-[10.5px] uppercase tracking-wider text-slate-400">{label}</dt>
              <dd className="text-2xl font-bold mt-0.5">{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      {/* Account, Security, Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-10">
        {/* Account */}
        <div className="surface p-6 flex flex-col">
          <div className="flex items-center gap-3 mb-5">
            <span className="icon-tile w-10 h-10"><User className="w-5 h-5" /></span>
            <div>
              <h2 className="text-base font-bold text-ink">Account Profile</h2>
              <p className="text-xs text-ink-muted">Identity and privilege</p>
            </div>
          </div>
          <div className="space-y-4 flex-1 text-sm">
            <div>
              <span className="meta-label">Full Name</span>
              <span className="font-semibold text-ink">{user?.name}</span>
            </div>
            <div>
              <span className="meta-label">Email Address</span>
              <span className="font-mono text-xs text-ink break-all">{user?.email}</span>
            </div>
            <div className="flex items-center justify-between pt-4 border-t border-line">
              <div>
                <span className="meta-label mb-1">Role</span>
                <span className="pill pill-neutral">{user?.is_admin ? "Administrator" : "Standard User"}</span>
              </div>
              <div className="text-right">
                <span className="meta-label mb-1">Status</span>
                <span className="pill pill-ok"><CheckCircle className="w-3 h-3" /> Active</span>
              </div>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="surface p-6 flex flex-col">
          <div className="flex items-center gap-3 mb-5">
            <span className="icon-tile w-10 h-10"><ShieldCheck className="w-5 h-5" /></span>
            <div>
              <h2 className="text-base font-bold text-ink">Active Security</h2>
              <p className="text-xs text-ink-muted">Protections in effect</p>
            </div>
          </div>
          <ul className="space-y-3 flex-1 text-xs text-ink">
            {guarantees.map(([title, text]) => (
              <li key={title} className="flex items-start gap-2.5">
                <CheckCircle className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
                <span><strong className="font-semibold">{title}:</strong> <span className="text-ink-muted">{text}</span></span>
              </li>
            ))}
          </ul>
        </div>

        {/* Activity */}
        <div className="surface p-6 flex flex-col">
          <div className="flex items-center gap-3 mb-5">
            <span className="icon-tile w-10 h-10"><History className="w-5 h-5" /></span>
            <div>
              <h2 className="text-base font-bold text-ink">Recent Activity</h2>
              <p className="text-xs text-ink-muted">Security audit events</p>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto max-h-56 pr-1 text-xs">
            {loadingActivity ? (
              <p className="text-ink-muted italic py-4 text-center">Loading audit events...</p>
            ) : activity.length === 0 ? (
              <p className="text-ink-muted italic py-4 text-center">No recent activity recorded.</p>
            ) : (
              <ul className="relative space-y-3 border-l border-line ml-1.5">
                {activity.map((item, idx) => (
                  <li key={idx} className="pl-4 relative">
                    <span className="absolute -left-[5px] top-1.5 w-2.5 h-2.5 rounded-full bg-lime border-2 border-white ring-1 ring-line-strong" />
                    <div className="flex justify-between items-start gap-2">
                      <span className="font-semibold text-ink">{formatAction(item.action)}</span>
                      <span className="text-[10px] text-ink-muted font-mono whitespace-nowrap">
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

      {/* Modules */}
      <section>
        <div className="mb-5">
          <p className="eyebrow text-ink-muted">Cryptographic modules</p>
          <h2 className="text-xl font-bold text-ink mt-1">Security Modules</h2>
          <p className="text-sm text-ink-muted mt-1">
            Certificates and encrypted file sharing are live; verification and decryption arrive in the next phase.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {modules.map(({ to, icon: Icon, title, text, cta, badge }) => (
            <Link key={title} to={to} className="group surface surface-hover p-5 flex flex-col">
              <div className="flex justify-between items-start mb-4">
                <span className="icon-tile w-10 h-10"><Icon className="w-5 h-5" /></span>
                <span className="pill pill-ok font-mono">{badge}</span>
              </div>
              <h3 className="font-bold text-sm text-ink mb-1">{title}</h3>
              <p className="text-xs text-ink-muted mb-4 flex-1">{text}</p>
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-navy group-hover:text-lime-dark">
                {cta}
                <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </span>
            </Link>
          ))}

          {/* Keys (informational, not a link) */}
          <div className="surface p-5 flex flex-col">
            <div className="flex justify-between items-start mb-4">
              <span className="icon-tile w-10 h-10"><KeyRound className="w-5 h-5" /></span>
              <span className="pill pill-ok font-mono">ACTIVE</span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">RSA Key Pair</h3>
            <p className="text-xs text-ink-muted mb-4 flex-1">
              RSA-3072 key generation and encrypted PKCS#8 private-key storage during account provisioning.
            </p>
            <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700">
              <Lock className="w-3.5 h-3.5" /> Keys provisioned securely
            </span>
          </div>

          {/* Certificate (informational link) */}
          <Link to="/directory" className="group surface surface-hover p-5 flex flex-col">
            <div className="flex justify-between items-start mb-4">
              <span className="icon-tile w-10 h-10"><Award className="w-5 h-5" /></span>
              <span className="pill pill-ok font-mono">LIVE</span>
            </div>
            <h3 className="font-bold text-sm text-ink mb-1">X.509 Certificate</h3>
            <p className="text-xs text-ink-muted mb-4 flex-1">
              Mini Certificate Authority issuance, verification, directory and revocation.
            </p>
            <span className="inline-flex items-center gap-1 text-xs font-semibold text-navy group-hover:text-lime-dark">
              Open certificate directory
              <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </span>
          </Link>
        </div>
      </section>
    </div>
  );
}
