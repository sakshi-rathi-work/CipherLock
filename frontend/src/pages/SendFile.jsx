// Provides the interface for sending files to recipients.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import {
  AlertTriangle,
  Award,
  CheckCircle2,
  FileUp,
  KeyRound,
  Lock,
  PenLine,
  HardDrive,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import Spinner from "../components/Spinner";
import {
  MAX_UPLOAD_BYTES,
  fileIconFor,
  formatBytes,
  formatTimestamp,
  newRequestId,
} from "../utils/files";

const PIPELINE = [
  { icon: Lock, title: "Encrypt", text: "A fresh AES-256-GCM key and nonce encrypt your file on the server." },
  { icon: KeyRound, title: "Wrap the key", text: "That key is sealed for the recipient with RSA-OAEP (SHA-256)." },
  { icon: PenLine, title: "Sign", text: "Your certificate’s key signs the package header with RSA-PSS." },
  { icon: HardDrive, title: "Store", text: "Only ciphertext is saved, under a random name. Plaintext is never written to disk." },
];

function validateFile(file) {
  if (!file) return "Choose a file to send.";
  if (file.size === 0) return "This file is empty. Empty files cannot be sent.";
  if (file.size > MAX_UPLOAD_BYTES) {
    return `This file is ${formatBytes(file.size)}. The maximum size is ${formatBytes(MAX_UPLOAD_BYTES)}.`;
  }
  return "";
}

export default function SendFile() {
  const { user } = useAuth();
  const fileInputRef = useRef(null);
  const submittingRef = useRef(false); // synchronous guard against double submits
  const requestIdRef = useRef(newRequestId()); // idempotency key for this attempt

  const [recipients, setRecipients] = useState([]);
  const [loadingRecipients, setLoadingRecipients] = useState(true);
  const [recipientsError, setRecipientsError] = useState("");

  const [file, setFile] = useState(null);
  const [recipientId, setRecipientId] = useState("");
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState("");
  const [recipientError, setRecipientError] = useState("");
  const [formError, setFormError] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);

  const loadRecipients = useCallback(async () => {
    setLoadingRecipients(true);
    setRecipientsError("");
    try {
      const res = await api.get("/users/directory");
      const eligible = (res.data?.users || []).filter(
        (u) => u.status === "active" && u.id !== user?.id
      );
      setRecipients(eligible);
    } catch (err) {
      setRecipientsError(err.userMessage || "Could not load recipients.");
    } finally {
      setLoadingRecipients(false);
    }
  }, [user?.id]);

  useEffect(() => {
    loadRecipients();
  }, [loadRecipients]);

  const selectedRecipient = useMemo(
    () => recipients.find((r) => String(r.id) === String(recipientId)) || null,
    [recipients, recipientId]
  );

  const chooseFile = (candidate) => {
    const problem = candidate ? validateFile(candidate) : "";
    setFileError(problem);
    setFormError("");
    setFile(problem ? null : candidate);
    requestIdRef.current = newRequestId(); // a different file is a different transfer
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const onDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    if (submitting) return;
    const dropped = event.dataTransfer?.files;
    if (dropped && dropped.length > 1) {
      setFileError("Drop a single file. Zip several files together to send them as one.");
      return;
    }
    if (dropped && dropped.length === 1) chooseFile(dropped[0]);
  };

  const onRecipientChange = (event) => {
    setRecipientId(event.target.value);
    setRecipientError("");
    setFormError("");
    requestIdRef.current = newRequestId();
  };

  const resetForm = () => {
    setFile(null);
    setRecipientId("");
    setResult(null);
    setFileError("");
    setRecipientError("");
    setFormError("");
    setProgress(0);
    requestIdRef.current = newRequestId();
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submittingRef.current) return; // ignore double clicks / Enter-spam

    const fileProblem = validateFile(file);
    const recipientProblem = selectedRecipient ? "" : "Choose a recipient.";
    setFileError(fileProblem);
    setRecipientError(recipientProblem);
    setFormError("");
    if (fileProblem || recipientProblem) return;

    submittingRef.current = true;
    setSubmitting(true);
    setProgress(0);

    const form = new FormData();
    form.append("file", file, file.name);
    form.append("recipient_id", String(selectedRecipient.id));
    form.append("client_request_id", requestIdRef.current);

    try {
      // No Content-Type header: the browser must add the multipart boundary itself.
      const res = await api.post("/files/upload", form, {
        onUploadProgress: (e) => {
          if (e.total) setProgress(Math.round((e.loaded / e.total) * 100));
        },
      });
      setResult(res.data);
      toast.success(res.data?.duplicate ? "This file was already sent." : "File encrypted and sent securely.");
    } catch (err) {
      const fields = err.fieldErrors || {};
      if (fields.file) setFileError(fields.file);
      if (fields.recipient_id) setRecipientError(fields.recipient_id);
      const message = !err.response
        ? "Could not reach the server. Check your connection and try again."
        : err.response.status === 413
        ? `The file is too large. The maximum size is ${formatBytes(MAX_UPLOAD_BYTES)}.`
        : fields.file || fields.recipient_id
        ? ""
        : err.userMessage || "The file could not be sent.";
      if (message) setFormError(message);
      toast.error(message || fields.file || fields.recipient_id || "The file could not be sent.");
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  };

  // ------------------------------------------------------------------ success summary
  if (result?.file) {
    const sent = result.file;
    const Icon = fileIconFor(sent.original_filename);
    return (
      <div className="page max-w-3xl">
        <div className="surface overflow-hidden" role="status">
          <div className="h-1.5 bg-gradient-to-r from-lime via-emerald-400 to-emerald-500" />
          <div className="p-6 sm:p-8">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-2xl bg-emerald-50 text-emerald-600 flex-shrink-0 ring-1 ring-emerald-200">
              <CheckCircle2 className="w-7 h-7" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold text-ink tracking-tight">
                {result.duplicate ? "This file was already sent" : "File sent securely"}
              </h1>
              <p className="text-sm text-ink-muted mt-1">
                {result.duplicate
                  ? "We recognised this request and did not create a second copy."
                  : "Your file was encrypted, signed and stored. Only the recipient can decrypt it."}
              </p>
            </div>
          </div>

          <dl className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4 text-sm">
            <div className="sm:col-span-2 flex items-center gap-3 p-3.5 rounded-xl bg-paper border border-line">
              <div className="icon-tile w-10 h-10"><Icon className="w-5 h-5" aria-hidden="true" /></div>
              <div className="min-w-0">
                <dt className="sr-only">File</dt>
                <dd className="font-semibold text-ink truncate">{sent.original_filename}</dd>
                <dd className="text-xs text-ink-muted font-mono">{formatBytes(sent.size_bytes)}</dd>
              </div>
            </div>
            <div>
              <dt className="meta-label mb-0.5">Recipient</dt>
              <dd className="font-semibold text-ink">{sent.receiver.name}</dd>
              <dd className="font-mono text-xs text-ink-muted">{sent.receiver.email}</dd>
            </div>
            <div>
              <dt className="meta-label mb-0.5">Sent</dt>
              <dd className="text-ink">{formatTimestamp(sent.created_at)}</dd>
            </div>
            <div>
              <dt className="meta-label mb-0.5">Status</dt>
              <dd>
                <span className="pill pill-ok">
                  Delivered · awaiting recipient verification
                </span>
              </dd>
            </div>
            <div>
              <dt className="meta-label mb-0.5">Transfer ID</dt>
              <dd className="font-mono text-ink">#{sent.id}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="meta-label mb-0.5">Protection applied</dt>
              <dd className="text-ink text-xs mt-1 space-y-0.5">
                <p>{sent.crypto?.encryption} file encryption</p>
                <p>{sent.crypto?.key_wrap} key wrapping</p>
                <p>{sent.crypto?.signature} signature</p>
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="meta-label mb-0.5">Ciphertext SHA-256</dt>
              <dd className="font-mono text-[11px] text-ink break-all bg-paper border border-line rounded-lg p-2.5">{sent.crypto?.ciphertext_sha256}</dd>
            </div>
          </dl>

          <div className="mt-8 flex flex-wrap gap-3">
            <button type="button" onClick={resetForm} className="btn-lime px-5 py-2.5 rounded-lg text-sm">
              Send another file
            </button>
            <Link to="/sent" className="btn-secondary">
              View sent files
            </Link>
          </div>
          </div>
        </div>
      </div>
    );
  }

  // ----------------------------------------------------------------------------- form
  const FileIcon = file ? fileIconFor(file.name) : FileUp;
  const canSubmit = !submitting && !loadingRecipients && recipients.length > 0;

  return (
    <div className="page max-w-6xl">
      <div className="mb-8">
        <p className="eyebrow text-lime-dark mb-2">Secure transfer</p>
        <h1 className="page-title">
          <span className="icon-tile w-11 h-11"><Upload className="w-5 h-5" aria-hidden="true" /></span> Send a file
        </h1>
        <p className="text-sm text-ink-muted mt-2 max-w-2xl">
          Pick a file and a recipient. CipherLock encrypts it for that person alone and signs it with your
          certificate, so they can confirm it really came from you and was not changed on the way.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        <form onSubmit={handleSubmit} noValidate className="lg:col-span-3 surface p-6 sm:p-7 space-y-6" aria-busy={submitting}>
          {formError && (
            <div role="alert" className="alert alert-error">
              <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <p>{formError}</p>
            </div>
          )}

          {/* File picker / dropzone */}
          <div>
            <label htmlFor="file-input" className="field-label">
              File
            </label>
            {!file ? (
              <label
                htmlFor="file-input"
                onDragOver={(e) => { e.preventDefault(); if (!submitting) setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={`flex flex-col items-center justify-center text-center rounded-2xl border-2 border-dashed px-6 py-12 cursor-pointer transition-all focus-within:ring-2 focus-within:ring-lime-dark ${
                  dragging ? "border-lime-dark bg-lime-tint scale-[1.01]" : fileError ? "border-red-300 bg-red-50" : "border-line-strong bg-paper/60 hover:border-lime-dark hover:bg-lime-tint/50"
                }`}
              >
                <div className="icon-tile w-14 h-14 mb-4"><FileUp className="w-6 h-6" aria-hidden="true" /></div>
                <span className="font-semibold text-ink">Drag a file here, or click to browse</span>
                <span className="text-xs text-ink-muted mt-1">Up to {formatBytes(MAX_UPLOAD_BYTES)}</span>
                <input
                  ref={fileInputRef}
                  id="file-input"
                  type="file"
                  className="sr-only"
                  disabled={submitting}
                  onChange={(e) => chooseFile(e.target.files?.[0] || null)}
                  aria-describedby={fileError ? "file-error" : undefined}
                  aria-invalid={Boolean(fileError)}
                />
              </label>
            ) : (
              <div className="flex items-center gap-3 rounded-xl border border-lime-dark/30 bg-lime-tint/60 p-4">
                <div className="icon-tile w-10 h-10"><FileIcon className="w-5 h-5" aria-hidden="true" /></div>
                <div className="min-w-0 flex-1">
                  <p className="font-semibold text-ink truncate" title={file.name}>{file.name}</p>
                  <p className="text-xs text-ink-muted font-mono">{formatBytes(file.size)}</p>
                </div>
                <button
                  type="button"
                  onClick={() => chooseFile(null)}
                  disabled={submitting}
                  className="p-2 rounded-lg text-ink-muted hover:text-red-600 hover:bg-white disabled:opacity-50 transition-colors"
                  aria-label={`Remove ${file.name}`}
                >
                  <X className="w-4 h-4" aria-hidden="true" />
                </button>
                {/* Kept mounted so the label above can be re-used after removal. */}
                <input ref={fileInputRef} id="file-input" type="file" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => chooseFile(e.target.files?.[0] || null)} />
              </div>
            )}
            {fileError && <p id="file-error" role="alert" className="text-xs text-red-600 mt-2">{fileError}</p>}
          </div>

          {/* Recipient */}
          <div>
            <label htmlFor="recipient" className="field-label">
              Recipient
            </label>
            {recipientsError ? (
              <div role="alert" className="alert alert-error items-center justify-between">
                <span>{recipientsError}</span>
                <button type="button" onClick={loadRecipients} className="text-xs font-semibold underline">Retry</button>
              </div>
            ) : (
              <select
                id="recipient"
                value={recipientId}
                onChange={onRecipientChange}
                disabled={submitting || loadingRecipients}
                className={`form-input ${recipientError ? "is-invalid" : ""}`}
                aria-invalid={Boolean(recipientError)}
                aria-describedby={recipientError ? "recipient-error" : undefined}
              >
                <option value="">
                  {loadingRecipients ? "Loading recipients…" : recipients.length ? "Select a recipient" : "No eligible recipients"}
                </option>
                {recipients.map((r) => (
                  <option key={r.id} value={r.id}>{r.name} — {r.email}</option>
                ))}
              </select>
            )}
            {recipientError && <p id="recipient-error" role="alert" className="text-xs text-red-600 mt-2">{recipientError}</p>}
            {!loadingRecipients && !recipientsError && recipients.length === 0 && (
              <p className="text-xs text-ink-muted mt-2">
                No other users with a valid certificate are registered yet. Ask the recipient to create an account first.
              </p>
            )}

            {selectedRecipient && (
              <div className="mt-3 rounded-xl border border-line bg-paper p-4 flex items-start gap-3">
                <div className="icon-tile w-9 h-9"><Award className="w-4 h-4" aria-hidden="true" /></div>
                <dl className="text-xs grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 min-w-0 flex-1">
                  <div className="min-w-0"><dt className="text-ink-muted">Name</dt><dd className="font-semibold text-ink truncate">{selectedRecipient.name}</dd></div>
                  <div className="min-w-0"><dt className="text-ink-muted">Email</dt><dd className="font-mono text-ink truncate">{selectedRecipient.email}</dd></div>
                  {/* cert_serial is deliberately not shown: the directory API sends ~159-bit serials as JSON numbers, which JavaScript cannot represent exactly. */}
                  <div className="min-w-0 sm:col-span-2"><dt className="text-ink-muted">Key fingerprint (SHA-256)</dt><dd className="font-mono text-ink break-all" title={selectedRecipient.fingerprint}>{selectedRecipient.fingerprint}</dd></div>
                  <div className="sm:col-span-2 flex items-center gap-1.5 text-emerald-700 font-medium">
                    <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" /> Certificate issued by the CipherLock Root CA · expires {formatTimestamp(selectedRecipient.expires_at)}
                  </div>
                </dl>
              </div>
            )}
          </div>

          {submitting && (
            <div aria-live="polite">
              <div className="h-2 rounded-full bg-paper-alt overflow-hidden" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
                <div className="h-full bg-gradient-to-r from-lime-dark to-lime transition-all" style={{ width: `${progress}%` }} />
              </div>
              <p className="text-xs text-ink-muted mt-2">
                {progress < 100 ? `Uploading… ${progress}%` : "Encrypting, wrapping the key and signing…"}
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={!canSubmit}
            className="btn-lime w-full sm:w-auto px-7 py-3 rounded-lg text-sm"
          >
            {submitting ? (
              <>
                <Spinner size="sm" className="border-navy border-t-transparent" /> Sending securely…
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" aria-hidden="true" /> Send Securely
              </>
            )}
          </button>
        </form>

        <aside className="lg:col-span-2">
          <div className="hero-surface p-6 lg:sticky lg:top-24">
            <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" aria-hidden="true" />
            <div className="relative">
            <p className="eyebrow text-lime mb-1">Under the hood</p>
            <h2 className="font-bold text-lg">What happens to your file</h2>
            <ol className="mt-5 space-y-5 relative">
              {PIPELINE.map(({ icon: StepIcon, title, text }, index) => (
                <li key={title} className="flex gap-3">
                  <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 text-lime flex items-center justify-center flex-shrink-0">
                    <StepIcon className="w-4 h-4" aria-hidden="true" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold"><span className="text-lime font-mono mr-1.5">{index + 1}.</span>{title}</p>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{text}</p>
                  </div>
                </li>
              ))}
            </ol>
            <p className="mt-6 pt-4 border-t border-white/10 text-xs text-slate-400 flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-lime flex-shrink-0" aria-hidden="true" />
              Your private key never leaves the server and is never sent to your browser.
            </p>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
