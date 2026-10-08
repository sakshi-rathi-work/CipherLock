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
    <div className="flex-1 py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      <div className="mb-8">
        <p className="eyebrow text-lime-dark mb-1">TRUST DIRECTORY</p>
        <h1 className="text-3xl font-extrabold text-ink flex items-center gap-3">
          <Users className="w-8 h-8 text-navy" /> Certificate Directory
        </h1>
        <p className="text-sm text-ink-muted mt-2 max-w-2xl">
          Every active CipherLock identity is backed by an X.509 certificate issued by the CipherLock Root CA.
        </p>
      </div>

      {error && <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}

      {loading ? (
        <div className="bg-white border border-line rounded-xl p-10 text-center text-ink-muted">Loading trusted identities…</div>
      ) : users.length === 0 ? (
        <div className="bg-white border border-line rounded-xl p-10 text-center text-ink-muted">No active certificates are available.</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {users.map((item) => (
            <Link key={item.id} to={`/directory/${item.id}`} className="group bg-white border border-line rounded-xl p-6 shadow-card hover:-translate-y-0.5 hover:shadow-panel transition-all">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-3 rounded-xl bg-navy text-lime"><Award className="w-5 h-5" /></div>
                  <div className="min-w-0">
                    <h2 className="font-bold text-ink truncate">{item.name}</h2>
                    <p className="text-xs text-ink-muted truncate">{item.email}</p>
                  </div>
                </div>
                {item.status === "active" ? <CheckCircle2 className="w-5 h-5 text-emerald-600" /> : <ShieldAlert className="w-5 h-5 text-amber-600" />}
              </div>
              <div className="mt-5 pt-4 border-t border-line grid grid-cols-2 gap-4 text-xs">
                <div><span className="block text-ink-muted uppercase font-mono">Certificate Serial</span><span className="font-mono text-ink break-all">{item.cert_serial}</span></div>
                <div><span className="block text-ink-muted uppercase font-mono">Fingerprint</span><span className="font-mono text-ink truncate block">{item.fingerprint?.slice(0, 18)}…</span></div>
              </div>
              <div className="mt-4 flex items-center text-xs font-semibold text-navy group-hover:text-lime-dark">Inspect certificate <ArrowRight className="w-3.5 h-3.5 ml-1" /></div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
