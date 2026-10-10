import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2, Copy, ShieldCheck, XCircle, Check as CheckIcon } from "lucide-react";
import { api } from "../api/client";

function Check({ label, ok }) {
  return (
    <div className="flex items-center gap-2.5 text-sm bg-white border border-line rounded-lg px-3.5 py-2.5">
      {ok ? (
        <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
      ) : (
        <XCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
      )}
      <span className={ok ? "text-ink" : "text-red-700"}>{label}</span>
    </div>
  );
}

export default function CertificateView() {
  const { userId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.get(`/users/${userId}/certificate`)
      .then((res) => setData(res.data))
      .catch((err) => setError(err.userMessage || "Certificate could not be loaded."));
  }, [userId]);

  const copyPem = async () => {
    if (!data?.certificate_pem) return;
    await navigator.clipboard.writeText(data.certificate_pem);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  if (error) {
    return (
      <div className="page max-w-4xl">
        <div role="alert" className="alert alert-error">{error}</div>
      </div>
    );
  }
  if (!data) return <div className="page max-w-4xl text-ink-muted">Loading certificate…</div>;

  const checks = data.verification;
  return (
    <div className="page max-w-5xl">
      <Link to="/directory" className="inline-flex items-center text-sm font-medium text-ink-muted hover:text-ink mb-6 transition-colors">
        <ArrowLeft className="w-4 h-4 mr-1.5" /> Back to directory
      </Link>

      <div className="surface overflow-hidden">
        <div className="hero-surface rounded-none shadow-none p-7 sm:p-8">
          <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" aria-hidden="true" />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <p className="eyebrow text-lime mb-1.5">X.509 identity record</p>
              <h1 className="text-2xl sm:text-3xl font-bold break-all">Certificate #{data.serial}</h1>
              <p className="text-sm text-slate-300 mt-1.5 break-all">{data.subject}</p>
            </div>
            <span
              className={`pill text-xs px-3.5 py-1.5 ${
                checks.valid
                  ? "border-emerald-400/40 bg-emerald-400/15 text-emerald-300"
                  : "border-red-400/40 bg-red-400/15 text-red-300"
              }`}
            >
              {checks.valid ? <ShieldCheck className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
              {checks.valid ? "TRUSTED" : "INVALID"}
            </span>
          </div>
        </div>

        <div className="p-6 sm:p-8 space-y-8">
          <section>
            <h2 className="font-bold text-ink mb-3 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-lime-dark" /> Verification chain
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 bg-paper border border-line rounded-2xl p-4">
              <Check label="Signed by CipherLock Root CA" ok={checks.ca_signature_ok} />
              <Check label="Within validity period" ok={checks.validity_ok} />
              <Check label="Not revoked" ok={checks.not_revoked} />
              <Check label="Expected identity matches" ok={checks.subject_ok} />
              <Check label="digitalSignature + keyEncipherment" ok={checks.key_usage_ok} />
            </div>
            {!checks.valid && <p className="alert alert-error mt-3">{checks.reason}</p>}
          </section>

          <section className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm border-t border-line pt-6">
            <div><span className="meta-label">Issuer</span><p className="font-medium text-ink mt-1">{data.issuer}</p></div>
            <div><span className="meta-label">Serial</span><p className="font-mono text-xs text-ink mt-1 break-all">{data.serial}</p></div>
            <div><span className="meta-label">Valid From</span><p className="text-ink mt-1">{new Date(data.not_valid_before).toLocaleString()}</p></div>
            <div><span className="meta-label">Valid Until</span><p className="text-ink mt-1">{new Date(data.not_valid_after).toLocaleString()}</p></div>
          </section>

          <section>
            <div className="flex justify-between items-center mb-3">
              <h2 className="font-bold text-ink">PEM certificate</h2>
              <button onClick={copyPem} className="btn-secondary !px-3 !py-1.5 text-xs">
                {copied ? <CheckIcon className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="bg-navy-deep text-lime/90 border border-navy-border rounded-2xl p-5 text-[11px] leading-relaxed overflow-x-auto font-mono shadow-inner">{data.certificate_pem}</pre>
          </section>
        </div>
      </div>
    </div>
  );
}
