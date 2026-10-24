import React, { useState } from "react";
import { Link } from "react-router-dom";
import { KeyRound, ShieldAlert } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

const attempts = [
  {
    id: "attacker",
    label: "Attacker's private key",
    result: "RSA-OAEP unwrap fails: this key does not match the recipient public key used to wrap the AES session key.",
  },
  {
    id: "random",
    label: "Random 256-bit key",
    result: "AES-256-GCM authentication fails: the random key does not authenticate the ciphertext tag.",
  },
  {
    id: "sender",
    label: "Sender's public key",
    result: "A public key cannot perform the recipient-only private-key unwrap operation.",
  },
];

export default function StolenData() {
  const { isAdmin } = useAuth();
  const [selected, setSelected] = useState("");
  const keyspace = (2n ** 256n).toString();

  if (!isAdmin) return <div className="page max-w-4xl"><div role="alert" className="alert alert-error">Administrator access required.</div></div>;

  return (
    <div className="page max-w-5xl space-y-6">
      <Link to="/admin" className="text-sm text-lime-dark hover:underline">← CA Administration</Link>
      <div>
        <p className="eyebrow text-lime-dark mb-2">Confidentiality demonstration</p>
        <h1 className="page-title"><KeyRound className="w-7 h-7 text-lime-dark" /> Stolen Data Analysis</h1>
        <p className="text-sm text-ink-muted mt-3">This explanatory simulation describes why ciphertext alone is not sufficient to recover a shared file.</p>
      </div>
      <div className="hero-surface p-6">
        <p className="font-mono text-xs uppercase tracking-wider text-slate-300">AES-256 session key search space</p>
        <p className="mt-3 text-2xl sm:text-3xl font-bold break-all">2<sup>256</sup> = {keyspace}</p>
        <p className="text-sm text-slate-300 mt-3">CipherLock wraps each file's random AES key for the intended receiver with RSA-OAEP. The ciphertext is authenticated by AES-GCM and the signed package metadata.</p>
      </div>
      <section className="surface p-6">
        <h2 className="font-bold text-ink">Try a hypothetical decryption path</h2>
        <p className="text-sm text-ink-muted mt-1">These are local educational outcomes only; no real file, key, or decryption request is used.</p>
        <div className="flex flex-wrap gap-2 mt-4">
          {attempts.map((attempt) => (
            <button key={attempt.id} className="btn-secondary" onClick={() => setSelected(attempt.id)}>{attempt.label}</button>
          ))}
        </div>
        {selected && (
          <div role="status" className="alert alert-warn mt-5">
            <ShieldAlert className="w-5 h-5 shrink-0" />
            <span>{attempts.find((attempt) => attempt.id === selected)?.result}</span>
          </div>
        )}
      </section>
      <p className="text-xs text-ink-muted">This is an educational work-factor illustration, not a claim that brute force is mathematically impossible or a measurement of real-world compute.</p>
    </div>
  );
}
