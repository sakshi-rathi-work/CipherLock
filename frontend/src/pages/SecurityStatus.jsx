// Security status dashboard and decryption screen (Phase 8).
import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, CheckCircle2, Download, KeyRound, Lock, ShieldAlert, ShieldCheck } from "lucide-react";
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
          <Spinner size="lg" className="border-lime border-t-transparent" />
          <p className="text-sm font-mono text-slate-400">Running cryptographic verification pipeline...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="page max-w-5xl">
        <div className="card p-6 border-rose-500/30 text-center">
          <ShieldAlert className="w-10 h-10 text-rose-400 mx-auto mb-3" />
          <h2 className="text-lg font-bold text-white mb-2">Verification Failed</h2>
          <p className="text-sm text-slate-400 mb-4">{error || "File could not be verified."}</p>
          <Link to="/received" className="btn btn-outline text-xs">
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
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <Link to="/received" className="inline-flex items-center gap-1.5 text-xs text-lime-dark hover:underline mb-2 font-mono">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Received Files
          </Link>
          <h1 className="page-title text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-lime" />
            Verification Pipeline
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Auditing {file?.original_filename} (ID: #{file?.id})
          </p>
        </div>
        <div>
          <span className={`px-3 py-1.5 rounded-full text-xs font-mono font-bold tracking-wider ${isTrusted ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-rose-500/10 text-rose-400 border border-rose-500/30"}`}>
            STATUS: {report?.overall}
          </span>
        </div>
      </div>

      {/* Overall Banner */}
      <div className={`card p-4 flex items-center justify-between border ${isTrusted ? "border-emerald-500/40 bg-emerald-950/20" : "border-rose-500/40 bg-rose-950/20"}`}>
        <div className="flex items-center gap-3">
          {isTrusted ? (
            <CheckCircle2 className="w-7 h-7 text-emerald-400 flex-shrink-0" />
          ) : (
            <ShieldAlert className="w-7 h-7 text-rose-400 flex-shrink-0" />
          )}
          <div>
            <h2 className="text-sm font-bold text-white">
              {isTrusted ? "CRYPTOGRAPHIC TRUST ESTABLISHED" : "VERIFICATION FAILED / UNTRUSTED"}
            </h2>
            <p className="text-xs text-slate-300 mt-0.5">
              {isTrusted
                ? "Digital signature, certificate provenance and ciphertext integrity checks passed cleanly."
                : "Signature verification failed. File may have been modified or sender authenticity could not be established."}
            </p>
          </div>
        </div>
      </div>

      {/* Sender Provenance */}
      <div className="card p-4 border border-navy-800">
        <h3 className="text-xs font-mono text-lime uppercase tracking-wider mb-3">Sender Provenance</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <div className="text-slate-500">Sender Name</div>
            <div className="font-semibold text-white mt-0.5">{sender?.name}</div>
          </div>
          <div>
            <div className="text-slate-500">Sender Email</div>
            <div className="font-mono text-slate-300 mt-0.5">{sender?.email}</div>
          </div>
          <div>
            <div className="text-slate-500">X.509 Certificate Serial</div>
            <div className="font-mono text-slate-300 mt-0.5 text-ellipsis overflow-hidden">{sender?.serial_number}</div>
          </div>
          <div>
            <div className="text-slate-500">Public Key Fingerprint</div>
            <div className="font-mono text-lime mt-0.5 text-ellipsis overflow-hidden">{sender?.fingerprint}</div>
          </div>
        </div>
      </div>

      {/* 3 Panels */}
      <SecurityPanel checks={checks} />

      {/* Monospace Audit Box */}
      <SecurityBox text={security_box} />

      {/* Decrypt & Download Section */}
      <div className="card p-5 border border-navy-700 bg-navy-900/60 shadow-lg" id="decrypt-form">
        <div className="flex items-center gap-2 pb-3 mb-4 border-b border-navy-800">
          <KeyRound className="w-5 h-5 text-lime" />
          <h2 className="font-bold text-white text-base">Decryption & Retrieval</h2>
        </div>

        {can_decrypt ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            <div className="lg:col-span-7 space-y-2 text-xs text-slate-300">
              <p>
                Verification has established that this file is authentic, from <strong>{sender?.name}</strong>, and unmodified.
              </p>
              <div className="p-3 rounded bg-navy-950 border border-navy-800 font-mono text-[11px] text-slate-400 space-y-1">
                <div className="text-lime font-bold">Decryption Execution Steps (Fail-Closed D7):</div>
                <div>1. Authenticate receiver password to unlock RSA-3072 private key in memory.</div>
                <div>2. Unwrap 256-bit AES session key using RSA-OAEP (SHA-256).</div>
                <div>3. Decrypt ciphertext payload using AES-256-GCM and verify authentication tag.</div>
                <div>4. Stream plaintext directly to browser memory (never written to server disk).</div>
              </div>
            </div>

            <div className="lg:col-span-5">
              <form onSubmit={handleDownload} className="space-y-3 bg-navy-950/80 p-4 rounded-xl border border-navy-800">
                <div>
                  <label htmlFor="decrypt-password" className="block text-xs font-medium text-slate-200 mb-1">
                    Enter Your Password to Decrypt:
                  </label>
                  <input
                    id="decrypt-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Account password"
                    required
                    className="form-input text-xs font-mono"
                    disabled={decrypting}
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Unlocked in-memory for this single request only.
                  </p>
                </div>

                {decryptError && (
                  <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                    {decryptError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={decrypting}
                  className="btn btn-primary w-full py-2.5 text-xs font-mono font-bold flex items-center justify-center gap-2"
                >
                  {decrypting ? (
                    <>
                      <Spinner size="sm" className="border-navy-950 border-t-transparent" />
                      <span>Decrypting & Streaming...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4" />
                      <span>Decrypt & Download</span>
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-start gap-3">
            <Lock className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-bold text-white">Decryption Refused (Fail-Closed Policy)</h4>
              <p className="text-xs text-rose-300 mt-1">
                Signature verification failed. File may have been modified or sender authenticity could not be established. Plaintext cannot and will not be decrypted.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
