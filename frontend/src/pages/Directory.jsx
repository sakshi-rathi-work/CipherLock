import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Award, ArrowRight, CheckCircle2, ShieldAlert, Users } from "lucide-react";
import { api } from "../api/client";

export default function Directory() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/users/directory")
      .then((res) => setUsers(res.data?.users || []))
      .catch((err) => setError(err.userMessage || "Could not load the certificate directory."))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="page max-w-7xl">
      <div className="mb-8">
        <p className="eyebrow text-lime-dark mb-2">Trust directory</p>
        <h1 className="page-title">
          <span className="icon-tile w-11 h-11"><Users className="w-5 h-5" /></span> Certificate Directory
        </h1>
        <p className="text-sm text-ink-muted mt-3 max-w-2xl">
          Every active CipherLock identity is backed by an X.509 certificate issued by the CipherLock Root CA.
        </p>
      </div>

      {error && <div role="alert" className="alert alert-error mb-6">{error}</div>}

      {loading ? (
        <div className="surface p-12 text-center text-ink-muted">Loading trusted identities…</div>
      ) : users.length === 0 ? (
        <div className="surface p-12 text-center text-ink-muted">No active certificates are available.</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {users.map((item) => (
            <Link key={item.id} to={`/directory/${item.id}`} className="group surface surface-hover p-6 flex flex-col">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="icon-tile w-12 h-12"><Award className="w-5 h-5" /></span>
                  <div className="min-w-0">
                    <h2 className="font-bold text-ink truncate">{item.name}</h2>
                    <p className="text-xs text-ink-muted truncate">{item.email}</p>
                  </div>
                </div>
                {item.status === "active" ? (
                  <span className="pill pill-ok"><CheckCircle2 className="w-3.5 h-3.5" /> Active</span>
                ) : (
                  <span className="pill pill-warn"><ShieldAlert className="w-3.5 h-3.5" /> {item.status}</span>
                )}
              </div>
              <div className="mt-5 pt-4 border-t border-line grid grid-cols-2 gap-4 text-xs flex-1">
                <div className="min-w-0">
                  <span className="meta-label mb-0.5">Certificate Serial</span>
                  <span className="font-mono text-ink break-all line-clamp-2">{item.cert_serial}</span>
                </div>
                <div className="min-w-0">
                  <span className="meta-label mb-0.5">Fingerprint</span>
                  <span className="font-mono text-ink truncate block">{item.fingerprint?.slice(0, 18)}…</span>
                </div>
              </div>
              <div className="mt-5 flex items-center text-xs font-semibold text-navy group-hover:text-lime-dark">
                Inspect certificate
                <ArrowRight className="w-3.5 h-3.5 ml-1 transition-transform group-hover:translate-x-1" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
