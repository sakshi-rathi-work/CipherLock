// Security status dashboard and decryption screen (Phase 8).
import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  KeyRound,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import toast from "react-hot-toast";
import { api } from "../api/client";
import SecurityPanel from "../components/SecurityPanel";
import SecurityBox from "../components/SecurityBox";
import Spinner from "../components/Spinner";

export default function SecurityStatus() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [password, setPassword] = useState("");
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState("");

  useEffect(() => {
    let active = true;
    async function fetchVerification() {
      setLoading(true);
      setError("");
      try {
        const res = await api.get(`/files/${id}/verify`);
        if (active) {
          setData(res.data);
        }
      } catch (err) {
        if (active) {
          setError(err.userMessage || "Failed to load cryptographic verification report.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    fetchVerification();
    return () => {
      active = false;
    };
  }, [id]);

  const handleDownload = async (e) => {
    e.preventDefault();
    if (!password) {
      setDecryptError("Password is required to decrypt the file.");
      return;
    }

    setDecrypting(true);
    setDecryptError("");

    try {
      const response = await api.post(
        `/files/${id}/download`,
        { password },
        { responseType: "blob" }
      );

      // Trigger browser download of streamed in-memory plaintext
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", data?.file?.original_filename || "decrypted_file");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      toast.success("File decrypted and downloaded successfully!");
      setPassword("");
    } catch (err) {
      let message = "Decryption failed.";
      if (err.response?.data instanceof Blob) {
        try {
          const text = await err.response.data.text();
          const parsed = JSON.parse(text);
          message = parsed.error || message;
        } catch {
          // fallback to generic
        }
      } else if (err.userMessage) {
        message = err.userMessage;
      }
      setDecryptError(message);
      toast.error(message);
    } finally {
      setDecrypting(false);
    }
  };

  if (loading) {
    return (
      <div className="page max-w-5xl flex items-center justify-center min-h-[50vh]">
        <div className="flex flex-col items-center gap-3">
          <Spinner size="lg" className="border-navy border-t-transparent" />
          <p className="text-sm font-mono text-ink-muted">Running cryptographic verification pipeline...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="page max-w-5xl">
        <div className="surface p-8 border-l-4 border-l-red-500 shadow-card text-center">
          <ShieldAlert className="w-12 h-12 text-red-600 mx-auto mb-3" />
          <h2 className="text-lg font-bold text-ink mb-2">Verification Failed</h2>
          <p className="text-sm text-ink-muted mb-5 max-w-md mx-auto">{error || "File could not be verified."}</p>
          <Link to="/received" className="btn-secondary text-xs">
            ← Return to Received Files
          </Link>
        </div>
      </div>
    );
  }

  const { file, sender, report, checks, security_box, can_decrypt } = data;
  const isTrusted = report?.overall === "TRUSTED";

  return (
    <div className="page max-w-5xl space-y-6">
      {/* Header and Breadcrumb */}
      <div>
        <Link
          to="/received"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink-muted hover:text-navy transition-colors mb-3 group font-mono"
        >
          <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-1" />
          Back to Received Files
        </Link>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <p className="eyebrow text-lime-dark mb-1">Receiver Cryptographic Pipeline</p>
            <h1 className="page-title text-2xl sm:text-3xl font-extrabold text-ink flex items-center gap-3">
              <span className="icon-tile w-11 h-11 shadow-sm">
                <ShieldCheck className="w-6 h-6 text-lime" />
              </span>
              Verification Pipeline
            </h1>
            <p className="text-xs sm:text-sm text-ink-muted font-mono mt-2">
              Auditing <strong className="text-ink font-semibold">{file?.original_filename}</strong>
              <span className="text-slate-400 mx-2">·</span>
              <span>ID #{file?.id}</span>
              {file?.created_at && (
                <>
                  <span className="text-slate-400 mx-2">·</span>
                  <span>Received {new Date(file.created_at).toLocaleString()}</span>
                </>
              )}
            </p>
          </div>
          <div className="flex-shrink-0">
            <span
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-mono font-bold tracking-wider uppercase border shadow-sm ${
                isTrusted
                  ? "bg-emerald-50 text-emerald-800 border-emerald-300"
                  : "bg-red-50 text-red-800 border-red-300"
              }`}
            >
              {isTrusted ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-red-600" />
              )}
              STATUS: {report?.overall || "UNTRUSTED"}
            </span>
          </div>
        </div>
      </div>

      {/* Overall Status Banner */}
      <div
        className={`surface p-5 border-l-4 shadow-card flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all ${
          isTrusted
            ? "border-l-emerald-500 bg-gradient-to-r from-emerald-50/70 via-white to-white"
            : "border-l-red-500 bg-gradient-to-r from-red-50/70 via-white to-white"
        }`}
      >
        <div className="flex items-center gap-3.5">
          <div
            className={`w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 shadow-sm ${
              isTrusted
                ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
                : "bg-red-100 text-red-700 border border-red-200"
            }`}
          >
            {isTrusted ? (
              <CheckCircle2 className="w-6 h-6" />
            ) : (
              <ShieldAlert className="w-6 h-6" />
            )}
          </div>
          <div>
            <h2
              className={`text-sm font-bold uppercase tracking-wider font-mono ${
                isTrusted ? "text-emerald-950" : "text-red-950"
              }`}
            >
              {isTrusted
                ? "Cryptographic Trust Established"
                : "Verification Failed / Untrusted"}
            </h2>
            <p className="text-xs text-ink-muted mt-1 leading-relaxed">
              {isTrusted
                ? "Digital signature, certificate provenance, and ciphertext SHA-256 integrity checks passed cleanly. The sender identity is verified and the encrypted file is intact."
                : "Signature verification failed. File may have been modified or sender authenticity could not be established."}
            </p>
          </div>
        </div>
        <div className="flex-shrink-0 self-start sm:self-center">
          <span
            className={`pill ${
              isTrusted ? "pill-ok" : "pill-bad"
            } font-mono text-xs px-3 py-1 font-bold`}
          >
            {isTrusted ? "TRUSTED" : report?.overall || "FAILED"}
          </span>
        </div>
      </div>

      {/* Sender Provenance */}
      <div className="surface p-5 sm:p-6 shadow-card">
        <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-line">
          <div className="flex items-center gap-2.5">
            <span className="icon-tile w-7 h-7 !rounded-lg">
              <Users className="w-4 h-4 text-lime" />
            </span>
            <h3 className="text-xs font-bold text-ink uppercase tracking-wider font-mono">
              Sender Provenance & Identity
            </h3>
          </div>
          <span className="pill pill-ok text-[11px] font-mono">
            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
            CA Certified Identity
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="bg-paper/70 p-3 rounded-xl border border-line">
            <span className="meta-label">Sender Name</span>
            <div className="font-semibold text-ink text-sm mt-1">{sender?.name || "Unknown"}</div>
          </div>
          <div className="bg-paper/70 p-3 rounded-xl border border-line">
            <span className="meta-label">Sender Email</span>
            <div className="font-mono text-ink text-xs font-medium mt-1 truncate" title={sender?.email}>
              {sender?.email}
            </div>
          </div>
          <div className="bg-paper/70 p-3 rounded-xl border border-line">
            <span className="meta-label">X.509 Certificate Serial</span>
            <div className="font-mono text-ink text-xs font-medium mt-1 truncate" title={sender?.serial_number}>
              {sender?.serial_number}
            </div>
          </div>
          <div className="bg-paper/70 p-3 rounded-xl border border-line">
            <span className="meta-label">Public Key Fingerprint</span>
            <div
              className="font-mono text-navy font-bold text-xs mt-1 bg-lime/30 px-2 py-0.5 rounded border border-lime/60 truncate"
              title={sender?.fingerprint}
            >
              {sender?.fingerprint ? `${sender.fingerprint.slice(0, 18)}...` : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* 3 Panels */}
      <SecurityPanel checks={checks} />

      {/* Monospace Audit Box */}
      <SecurityBox text={security_box} />

      {/* Decrypt & Download Section */}
      <div className="surface p-6 sm:p-7 shadow-panel border border-line" id="decrypt-form">
        <div className="flex items-center justify-between pb-4 mb-5 border-b border-line">
          <div className="flex items-center gap-3">
            <span className="icon-tile w-10 h-10 shadow-sm">
              <KeyRound className="w-5 h-5 text-lime" />
            </span>
            <div>
              <h2 className="font-extrabold text-ink text-lg tracking-tight">Decryption & File Retrieval</h2>
              <p className="text-xs text-ink-muted mt-0.5">
                In-memory RSA-OAEP session key unwrapping and AES-256-GCM authenticated plaintext streaming
              </p>
            </div>
          </div>
          {can_decrypt && (
            <span className="pill pill-ok font-mono text-xs px-3 py-1 font-bold">
              Ready to Decrypt
            </span>
          )}
        </div>

        {can_decrypt ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            <div className="lg:col-span-7 space-y-3 text-xs text-ink">
              <p className="leading-relaxed font-medium">
                Cryptographic verification has proven that this file is authentic, was signed by{" "}
                <strong className="text-ink font-bold">{sender?.name}</strong> (
                <span className="font-mono text-ink-muted">{sender?.email}</span>), and has not been modified.
              </p>
              <div className="p-4 rounded-xl bg-navy border border-navy-border font-mono text-xs text-slate-300 space-y-2 shadow-inner">
                <div className="text-lime font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5 pb-1 border-b border-navy-border/60">
                  <Lock className="w-3.5 h-3.5 text-lime" /> Decryption Execution Steps (Fail-Closed D7):
                </div>
                <div className="flex items-start gap-2 pt-1 text-[11.5px]">
                  <span className="text-lime font-bold">1.</span>
                  <span>Verify receiver account password to unlock RSA-3072 private key in memory.</span>
                </div>
                <div className="flex items-start gap-2 text-[11.5px]">
                  <span className="text-lime font-bold">2.</span>
                  <span>Unwrap 256-bit AES session key using RSA-OAEP (SHA-256 / MGF1).</span>
                </div>
                <div className="flex items-start gap-2 text-[11.5px]">
                  <span className="text-lime font-bold">3.</span>
                  <span>Decrypt ciphertext payload using AES-256-GCM and verify 16-byte authentication tag.</span>
                </div>
                <div className="flex items-start gap-2 text-[11.5px]">
                  <span className="text-lime font-bold">4.</span>
                  <span>Stream plaintext directly to browser memory (never written to server disk).</span>
                </div>
              </div>
            </div>

            <div className="lg:col-span-5">
              <form onSubmit={handleDownload} className="bg-paper border border-line rounded-2xl p-5 shadow-sm space-y-4">
                <div>
                  <label htmlFor="decrypt-password" className="field-label text-ink">
                    Enter Your Password to Decrypt:
                  </label>
                  <div className="relative mt-1">
                    <input
                      id="decrypt-password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Account password"
                      required
                      className="form-input text-xs font-mono pr-10"
                      disabled={decrypting}
                      autoComplete="current-password"
                    />
                    <KeyRound className="w-4 h-4 text-ink-muted absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  </div>
                  <p className="text-[11px] text-ink-muted mt-1.5 flex items-center gap-1.5 font-sans">
                    <ShieldCheck className="w-3.5 h-3.5 text-lime-dark flex-shrink-0" />
                    Unlocked in-memory for this single request only (D3).
                  </p>
                </div>

                {decryptError && (
                  <div className="alert alert-error text-xs py-2.5 px-3">
                    {decryptError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={decrypting}
                  className="btn-lime w-full py-3 px-4 rounded-xl text-xs font-mono font-bold flex items-center justify-center gap-2 shadow-lime"
                >
                  {decrypting ? (
                    <>
                      <Spinner size="sm" className="border-navy border-t-transparent" />
                      <span>Decrypting & Streaming...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4 text-navy" />
                      <span>Decrypt & Download Plaintext</span>
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="p-5 rounded-2xl bg-red-50 border-2 border-red-200 flex items-start gap-4 shadow-sm">
            <div className="w-11 h-11 rounded-xl bg-red-100 flex items-center justify-center text-red-700 flex-shrink-0 shadow-sm">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-red-900 uppercase font-mono tracking-wide">
                Decryption Refused (Fail-Closed Security Policy D7)
              </h4>
              <p className="text-xs text-red-800 mt-1 leading-relaxed">
                Signature verification failed. File may have been modified or sender authenticity could not be established. To preserve cryptographic integrity, private key session unwrapping is aborted and plaintext will never be decrypted.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
