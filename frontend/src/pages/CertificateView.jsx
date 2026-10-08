import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2, Copy, ShieldCheck, XCircle } from "lucide-react";
import { api } from "../api/client";

function Check({ label, ok }) {
  return <div className="flex items-center gap-2 text-sm">{ok ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <XCircle className="w-4 h-4 text-red-600" />}<span className={ok ? "text-ink" : "text-red-700"}>{label}</span></div>;
}

export default function CertificateView() {
  const { userId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get(`/users/${userId}/certificate`)
      .then((res) => setData(res.data))
      .catch((err) => setError(err.userMessage || "Certificate could not be loaded."));
  }, [userId]);

  const copyPem = async () => {
    if (!data?.certificate_pem) return;
    await navigator.clipboard.writeText(data.certificate_pem);
  };

  if (error) return <div className="max-w-4xl mx-auto w-full px-4 py-10"><div className="rounded-xl border border-red-200 bg-red-50 p-5 text-red-700">{error}</div></div>;
  if (!data) return <div className="max-w-4xl mx-auto w-full px-4 py-10 text-ink-muted">Loading certificate…</div>;

  const checks = data.verification;
  return (
    <div className="flex-1 py-10 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto w-full">
      <Link to="/directory" className="inline-flex items-center text-sm text-ink-muted hover:text-ink mb-6"><ArrowLeft className="w-4 h-4 mr-1" /> Back to directory</Link>
      <div className="bg-white border border-line rounded-2xl shadow-card overflow-hidden">
        <div className="bg-navy text-white p-7">
          <p className="eyebrow text-lime mb-1">X.509 IDENTITY RECORD</p>
          <div className="flex items-center justify-between gap-4">
            <div><h1 className="text-2xl font-bold">Certificate #{data.serial}</h1><p className="text-sm text-slate-300 mt-1">{data.subject}</p></div>
            <div className={`px-3 py-1.5 rounded-full text-xs font-bold ${checks.valid ? "bg-emerald-100 text-emerald-800" : "bg-red-100 text-red-800"}`}>{checks.valid ? "TRUSTED" : "INVALID"}</div>
          </div>
        </div>
        <div className="p-7 space-y-8">
          <section><h2 className="font-bold text-ink mb-3 flex items-center gap-2"><ShieldCheck className="w-5 h-5" /> Verification chain</h2><div className="grid grid-cols-1 sm:grid-cols-2 gap-3 bg-slate-50 rounded-xl p-5"><Check label="Signed by CipherLock Root CA" ok={checks.ca_signature_ok} /><Check label="Within validity period" ok={checks.validity_ok} /><Check label="Not revoked" ok={checks.not_revoked} /><Check label="Expected identity matches" ok={checks.subject_ok} /><Check label="digitalSignature + keyEncipherment" ok={checks.key_usage_ok} /></div>{!checks.valid && <p className="mt-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">{checks.reason}</p>}</section>
          <section className="grid grid-cols-1 md:grid-cols-2 gap-5 text-sm">
            <div><span className="text-xs uppercase font-mono text-ink-muted">Issuer</span><p className="font-medium text-ink mt-1">{data.issuer}</p></div>
            <div><span className="text-xs uppercase font-mono text-ink-muted">Serial</span><p className="font-mono text-ink mt-1 break-all">{data.serial}</p></div>
            <div><span className="text-xs uppercase font-mono text-ink-muted">Valid From</span><p className="text-ink mt-1">{new Date(data.not_valid_before).toLocaleString()}</p></div>
            <div><span className="text-xs uppercase font-mono text-ink-muted">Valid Until</span><p className="text-ink mt-1">{new Date(data.not_valid_after).toLocaleString()}</p></div>
          </section>
          <section><div className="flex justify-between items-center mb-2"><h2 className="font-bold text-ink">PEM certificate</h2><button onClick={copyPem} className="text-xs font-semibold text-navy inline-flex items-center gap-1"><Copy className="w-3.5 h-3.5" /> Copy</button></div><pre className="bg-[#071321] text-lime rounded-xl p-5 text-[11px] leading-relaxed overflow-x-auto">{data.certificate_pem}</pre></section>
        </div>
      </div>
    </div>
  );
}
