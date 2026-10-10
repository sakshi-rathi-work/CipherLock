import React, { useEffect, useState } from "react";
import { AlertTriangle, Ban, CheckCircle2, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "../../api/client";
import { useAuth } from "../../context/AuthContext";

export default function AdminPanel() {
  const { isAdmin } = useAuth();
  const [ca, setCa] = useState(null);
  const [certs, setCerts] = useState([]);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setBusy(true); setError("");
    try {
      const [caRes, certRes] = await Promise.all([api.get("/admin/ca-info"), api.get("/admin/certificates")]);
      setCa(caRes.data); setCerts(certRes.data?.certificates || []);
    } catch (err) { setError(err.userMessage || "Could not load CA administration data."); }
    finally { setBusy(false); }
  };
  useEffect(() => { if (isAdmin) load(); }, [isAdmin]);

  const revoke = async (serial) => {
    if (!window.confirm(`Revoke certificate ${serial}? This immediately removes its trust status.`)) return;
    try { await api.post(`/admin/certificates/${serial}/revoke`); await load(); }
    catch (err) { setError(err.userMessage || "Certificate revocation failed."); }
  };

  if (!isAdmin) {
    return (
      <div className="page max-w-4xl">
        <div role="alert" className="alert alert-error">Administrator access required.</div>
      </div>
    );
  }

  return (
    <div className="page max-w-7xl">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8">
        <div>
          <p className="eyebrow text-lime-dark mb-2">Root of trust</p>
          <h1 className="page-title">
            <span className="icon-tile w-11 h-11"><ShieldCheck className="w-5 h-5" /></span> CA Administration
          </h1>
          <p className="text-sm text-ink-muted mt-3">Inspect the mini-PKI and revoke compromised identities.</p>
        </div>
        <button onClick={load} className="btn-secondary">
          <RefreshCw className={`w-4 h-4 ${busy ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {error && <div role="alert" className="alert alert-error mb-6">{error}</div>}

      {busy ? (
        <div className="surface p-12 text-center text-ink-muted">Loading CA control plane…</div>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-7">
            <div className="hero-surface p-5">
              <KeyRound className="w-5 h-5 text-lime mb-5" />
              <p className="font-mono text-[10.5px] uppercase tracking-wider text-slate-400">Root key</p>
              <p className="text-2xl font-bold mt-0.5">RSA-{ca.key_size}</p>
            </div>
            <div className="surface p-5">
              <span className="inline-flex p-2 rounded-lg bg-emerald-50 text-emerald-600 mb-3"><CheckCircle2 className="w-5 h-5" /></span>
              <p className="meta-label">Active certificates</p>
              <p className="text-2xl font-bold text-ink mt-0.5">{ca.active_count}</p>
            </div>
            <div className="surface p-5">
              <span className="inline-flex p-2 rounded-lg bg-red-50 text-red-600 mb-3"><Ban className="w-5 h-5" /></span>
              <p className="meta-label">Revoked</p>
              <p className="text-2xl font-bold text-ink mt-0.5">{ca.revoked_count}</p>
            </div>
          </div>

          <div className="surface overflow-hidden">
            <div className="p-6 border-b border-line">
              <h2 className="font-bold text-ink">Certificate inventory</h2>
              <p className="text-xs text-ink-muted mt-1">
                Root: {ca.subject} · Expires {new Date(ca.not_valid_after).toLocaleDateString()}
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-paper text-[10.5px] uppercase font-mono tracking-wider text-ink-muted">
                  <tr>
                    <th className="text-left px-5 py-3.5">Identity</th>
                    <th className="text-left px-5 py-3.5">Serial</th>
                    <th className="text-left px-5 py-3.5">Validity</th>
                    <th className="text-left px-5 py-3.5">Status</th>
                    <th className="text-right px-5 py-3.5">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {certs.map((c) => (
                    <tr key={c.id} className="hover:bg-paper/70 transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-semibold text-ink">{c.name}</div>
                        <div className="text-xs text-ink-muted">{c.email}</div>
                      </td>
                      <td className="px-5 py-4 font-mono text-xs break-all max-w-[220px]">{c.serial}</td>
                      <td className="px-5 py-4 text-xs text-ink-muted whitespace-nowrap">
                        {new Date(c.issued_at).toLocaleDateString()} → {new Date(c.expires_at).toLocaleDateString()}
                      </td>
                      <td className="px-5 py-4">
                        {c.status === "active" && c.verification_valid ? (
                          <span className="pill pill-ok"><ShieldCheck className="w-3.5 h-3.5" /> TRUSTED</span>
                        ) : (
                          <span className="pill pill-bad"><AlertTriangle className="w-3.5 h-3.5" /> {c.status.toUpperCase()}</span>
                        )}
                      </td>
                      <td className="px-5 py-4 text-right">
                        {c.status === "active" && (
                          <button
                            onClick={() => revoke(c.serial)}
                            className="text-xs font-semibold text-red-700 hover:text-white hover:bg-red-600 border border-red-200 rounded-lg px-3 py-1.5 transition-colors"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
