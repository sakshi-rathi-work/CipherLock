import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, RotateCcw, ShieldAlert } from "lucide-react";
import { api } from "../../api/client";
import { useAuth } from "../../context/AuthContext";

const attacks = [
  ["tamper-ciphertext", "Flip ciphertext byte"],
  ["tamper-metadata", "Change signed filename"],
  ["tamper-signature", "Corrupt signature"],
  ["swap-cert", "Swap sender certificate"],
];

export default function AttackLab() {
  const { isAdmin } = useAuth();
  const [files, setFiles] = useState([]);
  const [fileId, setFileId] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.get("/admin/lab/files");
      setFiles(response.data?.files || []);
      setFileId((current) => current || String(response.data?.files?.[0]?.id || ""));
    } catch (err) {
      setError(err.userMessage || "The local attack lab is unavailable. Enable DEMO_MODE=1 to use it.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { if (isAdmin) load(); }, [isAdmin]);

  const run = async (action) => {
    if (!fileId) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const response = await api.post(`/admin/lab/${action}`, { file_id: Number(fileId) });
      setResult(action === "restore" ? "Original encrypted package restored. Ask the recipient to verify it again." : `${response.data.message}. Ask the recipient to verify file #${fileId}; the download must be refused.`);
      await load();
    } catch (err) {
      setError(err.userMessage || "The demonstration action failed.");
    } finally {
      setBusy(false);
    }
  };

  if (!isAdmin) return <div className="page max-w-4xl"><div role="alert" className="alert alert-error">Administrator access required.</div></div>;

  return (
    <div className="page max-w-5xl space-y-6">
      <Link to="/admin" className="text-sm text-lime-dark hover:underline">← CA Administration</Link>
      <div>
        <p className="eyebrow text-red-700 mb-2">DEMO_MODE only</p>
        <h1 className="page-title"><ShieldAlert className="w-7 h-7 text-red-600" /> Attacker Simulation Lab</h1>
        <p className="text-sm text-ink-muted mt-3">Controlled, reversible tampering against this local app's stored encrypted files. No external targets are contacted.</p>
      </div>
      <div role="alert" className="alert alert-warn">
        <AlertTriangle className="w-5 h-5 shrink-0" />
        These controls deliberately modify a selected file record or ciphertext. Use only in a disposable demo environment; restore after each demonstration.
      </div>
      {error && <div role="alert" className="alert alert-error">{error}</div>}
      {result && <div role="status" className="alert alert-success">{result}</div>}
      {loading ? (
        <div className="surface p-8 text-center text-ink-muted">Loading local demo files…</div>
      ) : (
        <section className="surface p-6 space-y-5">
          <label className="block">
            <span className="field-label">Select stored file</span>
            <select className="form-input" value={fileId} onChange={(event) => setFileId(event.target.value)} disabled={!files.length}>
              {files.map((file) => (
                <option key={file.id} value={file.id}>
                  #{file.id} · {file.original_filename} · {file.sender_name} → {file.receiver_name} · {file.status}
                </option>
              ))}
            </select>
          </label>
          {!files.length && <p className="text-sm text-ink-muted">Upload a local demo file first; no file contents are exposed by this list.</p>}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {attacks.map(([action, label]) => (
              <button key={action} className="btn-secondary justify-start" onClick={() => run(action)} disabled={!fileId || busy}>
                {label}
              </button>
            ))}
            <button className="btn-dark sm:col-span-2" onClick={() => run("restore")} disabled={!fileId || busy}>
              <RotateCcw className="w-4 h-4" /> Restore original package
            </button>
          </div>
          {fileId && (
            <p className="text-xs text-ink-muted">
              Verification page for the selected recipient: <code className="font-mono">/files/{fileId}/verify</code>. Sign in as that recipient to view the result.
            </p>
          )}
        </section>
      )}
    </div>
  );
}
