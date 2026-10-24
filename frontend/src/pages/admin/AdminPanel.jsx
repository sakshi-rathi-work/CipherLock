import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Ban, CheckCircle2, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "../../api/client";
import { useAuth } from "../../context/AuthContext";

export default function AdminPanel() {
  const { isAdmin } = useAuth();
  const [ca, setCa] = useState(null);
  const [certs, setCerts] = useState([]);
  const [users, setUsers] = useState([]);
  const [events, setEvents] = useState([]);
  const [certStatus, setCertStatus] = useState("");
  const [activityQuery, setActivityQuery] = useState("");
  const [activitySearch, setActivitySearch] = useState("");
  const [selectedUser, setSelectedUser] = useState(null);
  const [adminPassword, setAdminPassword] = useState("");
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = async (status = certStatus, query = activitySearch) => {
    setBusy(true);
    setError("");
    try {
      const [caRes, certRes, userRes, activityRes] = await Promise.all([
        api.get("/admin/ca-info"),
        api.get("/admin/certificates", { params: status ? { status } : {} }),
        api.get("/admin/users"),
        api.get("/admin/activity", { params: query ? { q: query } : {} }),
      ]);
      setCa(caRes.data);
      setCerts(certRes.data?.certificates || []);
      setUsers(userRes.data?.users || []);
      setEvents(activityRes.data?.events || []);
    } catch (err) {
      setError(err.userMessage || "Could not load administrator data.");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (isAdmin) load();
  }, [isAdmin]);

  const revoke = async (serial) => {
    if (!window.confirm(`Revoke certificate ${serial}? This immediately removes its trust status.`)) return;
    try {
      await api.post(`/admin/certificates/${serial}/revoke`);
      setNotice("Certificate revoked.");
      await load();
    } catch (err) {
      setError(err.userMessage || "Certificate revocation failed.");
    }
  };

  const setActive = async (user) => {
    const next = !user.is_active;
    if (!window.confirm(`${next ? "Enable" : "Disable"} ${user.name}'s account?`)) return;
    try {
      await api.post(`/admin/users/${user.id}/toggle-active`, { is_active: next });
      setNotice(`Account ${next ? "enabled" : "disabled"}.`);
      await load();
    } catch (err) {
      setError(err.userMessage || "Account status update failed.");
    }
  };

  const reissue = async (event) => {
    event.preventDefault();
    if (!selectedUser || !adminPassword) return;
    try {
      await api.post(`/admin/users/${selectedUser.id}/certificates/reissue`, { password: adminPassword });
      setNotice(`Certificate reissued for ${selectedUser.name}.`);
      setSelectedUser(null);
      setAdminPassword("");
      await load();
    } catch (err) {
      setError(err.userMessage || "Certificate reissue failed.");
    }
  };

  const searchActivity = (event) => {
    event.preventDefault();
    setActivitySearch(activityQuery.trim());
    load(certStatus, activityQuery.trim());
  };

  if (!isAdmin) {
    return (
      <div className="page max-w-4xl">
        <div role="alert" className="alert alert-error">Administrator access required.</div>
      </div>
    );
  }

  return (
    <div className="page max-w-7xl space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <p className="eyebrow text-lime-dark mb-2">Root of trust</p>
          <h1 className="page-title">
            <span className="icon-tile w-11 h-11"><ShieldCheck className="w-5 h-5" /></span> CA Administration
          </h1>
          <p className="text-sm text-ink-muted mt-3">Manage accounts, inspect the mini-PKI, and review security events.</p>
        </div>
        <button onClick={() => load()} className="btn-secondary" disabled={busy}>
          <RefreshCw className={`w-4 h-4 ${busy ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {error && <div role="alert" className="alert alert-error">{error}</div>}
      {notice && <div role="status" className="alert alert-success">{notice}</div>}
      {busy && !ca ? (
        <div className="surface p-12 text-center text-ink-muted">Loading CA control plane…</div>
      ) : ca ? (
        <>
          {ca.demo_mode && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Link to="/admin/attack-lab" className="surface surface-hover p-5">
                <p className="font-bold text-ink">Attacker Simulation Lab</p>
                <p className="text-sm text-ink-muted mt-1">Run reversible tampering demonstrations on stored ciphertext.</p>
              </Link>
              <Link to="/admin/stolen-data" className="surface surface-hover p-5">
                <p className="font-bold text-ink">Stolen Data Analysis</p>
                <p className="text-sm text-ink-muted mt-1">Explore why wrapped AES keys cannot be recovered by guessing.</p>
              </Link>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
            <div className="hero-surface p-5">
              <KeyRound className="w-5 h-5 text-lime mb-5" />
              <p className="font-mono text-[10.5px] uppercase tracking-wider text-slate-400">Root key</p>
              <p className="text-2xl font-bold mt-0.5">RSA-{ca.key_size}</p>
            </div>
            <div className="surface p-5">
              <span className="inline-flex p-2 rounded-lg bg-emerald-50 text-emerald-600 mb-3"><CheckCircle2 className="w-5 h-5" /></span>
              <p className="meta-label">Active certificates</p>
              <p className="text-2xl font-bold text-ink mt-0.5">{ca.active_count}</p>
            </div>
            <div className="surface p-5">
              <span className="inline-flex p-2 rounded-lg bg-red-50 text-red-600 mb-3"><Ban className="w-5 h-5" /></span>
              <p className="meta-label">Revoked certificates</p>
              <p className="text-2xl font-bold text-ink mt-0.5">{ca.revoked_count}</p>
            </div>
          </div>

          <section className="surface overflow-hidden">
            <div className="p-6 border-b border-line flex flex-col sm:flex-row sm:items-end justify-between gap-3">
              <div>
                <h2 className="font-bold text-ink">Certificate inventory</h2>
                <p className="text-xs text-ink-muted mt-1">Root: {ca.subject} · Expires {new Date(ca.not_valid_after).toLocaleDateString()}</p>
              </div>
              <label className="text-xs text-ink-muted">
                Filter status
                <select
                  className="form-input mt-1"
                  value={certStatus}
                  onChange={(event) => {
                    setCertStatus(event.target.value);
                    load(event.target.value, activitySearch);
                  }}
                >
                  <option value="">All statuses</option>
                  <option value="active">Active</option>
                  <option value="revoked">Revoked</option>
                  <option value="expired">Expired</option>
                </select>
              </label>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-paper text-[10.5px] uppercase font-mono tracking-wider text-ink-muted">
                  <tr>
                    <th className="text-left px-5 py-3.5">Identity</th>
                    <th className="text-left px-5 py-3.5">Serial</th>
                    <th className="text-left px-5 py-3.5">Validity</th>
                    <th className="text-left px-5 py-3.5">Status</th>
                    <th className="text-right px-5 py-3.5">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {certs.map((cert) => (
                    <tr key={cert.id}>
                      <td className="px-5 py-4">
                        <div className="font-semibold text-ink">{cert.name}</div>
                        <div className="text-xs text-ink-muted">{cert.email}</div>
                      </td>
                      <td className="px-5 py-4 font-mono text-xs break-all max-w-[220px]">{cert.serial}</td>
                      <td className="px-5 py-4 text-xs text-ink-muted whitespace-nowrap">
                        {new Date(cert.issued_at).toLocaleDateString()} → {new Date(cert.expires_at).toLocaleDateString()}
                      </td>
                      <td className="px-5 py-4">
                        {cert.status === "active" && cert.verification_valid ? (
                          <span className="pill pill-ok"><ShieldCheck className="w-3.5 h-3.5" /> TRUSTED</span>
                        ) : (
                          <span className="pill pill-bad"><AlertTriangle className="w-3.5 h-3.5" /> {cert.status.toUpperCase()}</span>
                        )}
                      </td>
                      <td className="px-5 py-4 text-right">
                        {cert.status === "active" && (
                          <button onClick={() => revoke(cert.serial)} className="text-xs font-semibold text-red-700 hover:text-white hover:bg-red-600 border border-red-200 rounded-lg px-3 py-1.5">
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {!certs.length && <tr><td colSpan="5" className="px-5 py-8 text-center text-ink-muted">No certificates match this filter.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>

          <section className="surface overflow-hidden">
            <div className="p-6 border-b border-line">
              <h2 className="font-bold text-ink">Account management</h2>
              <p className="text-xs text-ink-muted mt-1">Account state changes take effect on the next authenticated request.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-paper text-[10.5px] uppercase font-mono tracking-wider text-ink-muted">
                  <tr><th className="text-left px-5 py-3">User</th><th className="text-left px-5 py-3">Role</th><th className="text-left px-5 py-3">State</th><th className="text-right px-5 py-3">Actions</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td className="px-5 py-4"><div className="font-semibold">{user.name}</div><div className="text-xs text-ink-muted">{user.email}</div></td>
                      <td className="px-5 py-4">{user.is_admin ? "Administrator" : "User"}</td>
                      <td className="px-5 py-4">{user.is_active ? "Active" : "Disabled"}</td>
                      <td className="px-5 py-4 text-right space-x-2">
                        <button onClick={() => setActive(user)} className="btn-secondary text-xs py-1.5">
                          {user.is_active ? "Disable" : "Enable"}
                        </button>
                        <button onClick={() => setSelectedUser(user)} className="btn-secondary text-xs py-1.5">
                          Reissue certificate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="surface overflow-hidden">
            <div className="p-6 border-b border-line">
              <h2 className="font-bold text-ink">Searchable activity log</h2>
              <form onSubmit={searchActivity} className="flex gap-2 mt-3">
                <input className="form-input" value={activityQuery} onChange={(event) => setActivityQuery(event.target.value)} maxLength={100} placeholder="Search action, user, or event details" aria-label="Search activity log" />
                <button className="btn-secondary" type="submit">Search</button>
              </form>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-paper text-[10.5px] uppercase font-mono tracking-wider text-ink-muted">
                  <tr><th className="text-left px-5 py-3">Time</th><th className="text-left px-5 py-3">User</th><th className="text-left px-5 py-3">Action</th><th className="text-left px-5 py-3">Details</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {events.map((event) => (
                    <tr key={event.id}>
                      <td className="px-5 py-3 whitespace-nowrap text-xs text-ink-muted">{new Date(event.created_at).toLocaleString()}</td>
                      <td className="px-5 py-3">{event.name || "System"}<div className="text-xs text-ink-muted">{event.email || ""}</div></td>
                      <td className="px-5 py-3 font-mono text-xs">{event.action}</td>
                      <td className="px-5 py-3 text-xs break-all">{event.detail}</td>
                    </tr>
                  ))}
                  {!events.length && <tr><td colSpan="4" className="px-5 py-8 text-center text-ink-muted">No activity matches this search.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        </>
      ) : null}

      {selectedUser && (
        <div className="fixed inset-0 z-[60] bg-navy/70 p-4 flex items-center justify-center" role="presentation">
          <form onSubmit={reissue} className="surface w-full max-w-md p-6 space-y-4" role="dialog" aria-modal="true" aria-labelledby="reissue-title">
            <h2 id="reissue-title" className="text-lg font-bold">Reissue certificate</h2>
            <p className="text-sm text-ink-muted">A new certificate will be issued for {selectedUser.name}; active certificates for this account will be revoked. Confirm with your administrator password.</p>
            <label className="field-label" htmlFor="admin-password">Administrator password</label>
            <input id="admin-password" className="form-input" type="password" autoComplete="current-password" value={adminPassword} onChange={(event) => setAdminPassword(event.target.value)} required />
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-secondary" onClick={() => { setSelectedUser(null); setAdminPassword(""); }}>Cancel</button>
              <button type="submit" className="btn-dark">Confirm reissue</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
