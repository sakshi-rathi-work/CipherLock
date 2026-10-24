// Panels for Certificate, Signature, and Integrity verification (Phase 8).
import React from "react";
import { Check, X, Shield, FileCheck, Award } from "lucide-react";

function CheckItem({ label, passed, valueText }) {
  return (
    <li className="flex items-center justify-between py-2 border-b border-navy-800 last:border-b-0 text-xs">
      <span className="text-slate-300">{label}</span>
      {valueText ? (
        <span className="text-slate-400 font-mono text-[11px]">{valueText}</span>
      ) : passed ? (
        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
          <Check className="w-3.5 h-3.5" aria-hidden="true" /> Valid
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 text-rose-400 font-medium">
          <X className="w-3.5 h-3.5" aria-hidden="true" /> Failed
        </span>
      )}
    </li>
  );
}

export default function SecurityPanel({ checks }) {
  const { certificate = {}, signature = {}, integrity = {} } = checks || {};

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* 1. Certificate Panel */}
      <div className={`card p-4 border ${certificate.status === "VALID" ? "border-emerald-500/30" : "border-rose-500/30"}`}>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-navy-800">
          <div className="flex items-center gap-2">
            <Award className={`w-4 h-4 ${certificate.status === "VALID" ? "text-emerald-400" : "text-rose-400"}`} />
            <h3 className="font-semibold text-white text-sm uppercase tracking-wider">Certificate</h3>
          </div>
          <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${certificate.status === "VALID" ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"}`}>
            {certificate.status || "UNKNOWN"}
          </span>
        </div>
        <ul className="space-y-1">
          <CheckItem label="CipherLock Root CA signature" passed={certificate.ca_signature_ok} />
          <CheckItem label="Validity period (not expired)" passed={certificate.validity_ok} />
          <CheckItem label="Certificate revocation status" passed={certificate.not_revoked} />
          <CheckItem label="Subject matches sender" passed={certificate.subject_ok} />
          <CheckItem label="Key usage (digitalSignature)" passed={certificate.key_usage_ok} />
          <CheckItem label="Serial binding in header" passed={certificate.serial_matches} />
        </ul>
      </div>

      {/* 2. Signature Panel */}
      <div className={`card p-4 border ${signature.status === "VALID" ? "border-emerald-500/30" : "border-rose-500/30"}`}>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-navy-800">
          <div className="flex items-center gap-2">
            <FileCheck className={`w-4 h-4 ${signature.status === "VALID" ? "text-emerald-400" : "text-rose-400"}`} />
            <h3 className="font-semibold text-white text-sm uppercase tracking-wider">Signature</h3>
          </div>
          <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${signature.status === "VALID" ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"}`}>
            {signature.status || "UNKNOWN"}
          </span>
        </div>
        <ul className="space-y-1">
          <CheckItem label="RSA-PSS digital signature" passed={signature.signature_ok} />
          <CheckItem label="Algorithm parameters" valueText="SHA-256 / 32B salt" />
          <CheckItem label="Canonical JSON header" passed={signature.canonical_header_ok} />
          <CheckItem label="Sender public key certified" passed={signature.signature_ok && certificate.ca_signature_ok} />
        </ul>
      </div>

      {/* 3. Integrity Panel */}
      <div className={`card p-4 border ${integrity.status === "PASSED" ? "border-emerald-500/30" : "border-rose-500/30"}`}>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-navy-800">
          <div className="flex items-center gap-2">
            <Shield className={`w-4 h-4 ${integrity.status === "PASSED" ? "text-emerald-400" : "text-rose-400"}`} />
            <h3 className="font-semibold text-white text-sm uppercase tracking-wider">Integrity</h3>
          </div>
          <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${integrity.status === "PASSED" ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"}`}>
            {integrity.status || "UNKNOWN"}
          </span>
        </div>
        <ul className="space-y-1">
          <CheckItem label="Recomputed ciphertext SHA-256" passed={integrity.hash_matches} />
          <CheckItem label="Disk payload intact" passed={integrity.payload_intact} />
          <CheckItem label="GCM 16-byte auth tag" valueText="Verified on open" />
          <CheckItem label="Hash computation source" valueText="Stored .bin bytes" />
        </ul>
      </div>
    </div>
  );
}
