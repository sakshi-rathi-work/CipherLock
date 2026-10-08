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

  if (!isAdmin) return <div className="max-w-4xl mx-auto px-4 py-10"><div className="rounded-xl border border-red-200 bg-red-50 p-5 text-red-700">Administrator access required.</div></div>;

  return <div className="flex-1 py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
    <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8"><div><p className="eyebrow text-lime-dark mb-1">ROOT OF TRUST</p><h1 className="text-3xl font-extrabold text-ink">CA Administration</h1><p className="text-sm text-ink-muted mt-2">Inspect the mini-PKI and revoke compromised identities.</p></div><button onClick={load} className="px-4 py-2 rounded-lg border border-line bg-white text-sm font-semibold inline-flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Refresh</button></div>
    {error && <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}
    {busy ? <div className="bg-white border border-line rounded-xl p-10 text-center text-ink-muted">Loading CA control plane…</div> : <>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-7">
        <div className="bg-navy text-white rounded-xl p-5"><KeyRound className="w-5 h-5 text-lime mb-4" /><p className="text-xs text-slate-300">ROOT KEY</p><p className="text-xl font-bold">RSA-{ca.key_size}</p></div>
        <div className="bg-white border border-line rounded-xl p-5"><CheckCircle2 className="w-5 h-5 text-emerald-600 mb-4" /><p className="text-xs text-ink-muted">ACTIVE CERTIFICATES</p><p className="text-2xl font-bold text-ink">{ca.active_count}</p></div>
        <div className="bg-white border border-line rounded-xl p-5"><Ban className="w-5 h-5 text-red-600 mb-4" /><p className="text-xs text-ink-muted">REVOKED</p><p className="text-2xl font-bold text-ink">{ca.revoked_count}</p></div>
      </div>
      <div className="bg-white border border-line rounded-xl shadow-card overflow-hidden"><div className="p-6 border-b border-line"><h2 className="font-bold text-ink">Certificate inventory</h2><p className="text-xs text-ink-muted mt-1">Root: {ca.subject} · Expires {new Date(ca.not_valid_after).toLocaleDateString()}</p></div><div className="overflow-x-auto"><table className="w-full text-sm"><thead className="bg-slate-50 text-xs uppercase font-mono text-ink-muted"><tr><th className="text-left p-4">Identity</th><th className="text-left p-4">Serial</th><th className="text-left p-4">Validity</th><th className="text-left p-4">Status</th><th className="text-right p-4">Action</th></tr></thead><tbody className="divide-y divide-line">{certs.map((c) => <tr key={c.id}><td className="p-4"><div className="font-semibold text-ink">{c.name}</div><div className="text-xs text-ink-muted">{c.email}</div></td><td className="p-4 font-mono text-xs">{c.serial}</td><td className="p-4 text-xs">{new Date(c.issued_at).toLocaleDateString()} → {new Date(c.expires_at).toLocaleDateString()}</td><td className="p-4">{c.status === "active" && c.verification_valid ? <span className="inline-flex items-center gap-1 text-emerald-700 text-xs font-bold"><ShieldCheck className="w-3.5 h-3.5" /> TRUSTED</span> : <span className="inline-flex items-center gap-1 text-red-700 text-xs font-bold"><AlertTriangle className="w-3.5 h-3.5" /> {c.status.toUpperCase()}</span>}</td><td className="p-4 text-right">{c.status === "active" && <button onClick={() => revoke(c.serial)} className="text-xs font-bold text-red-700 hover:text-red-900">Revoke</button>}</td></tr>)}</tbody></table></div></div>
    </>}
  </div>;
}
