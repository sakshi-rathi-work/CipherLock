// Panels for Certificate, Signature, and Integrity verification (Phase 8).
import React from "react";
import { Check, X, Shield, FileCheck, Award } from "lucide-react";

function CheckItem({ label, passed, valueText }) {
  return (
    <li className="flex items-center justify-between py-2 border-b border-line/70 last:border-b-0 text-xs gap-2">
      <span className="text-ink-muted font-medium">{label}</span>
      {valueText ? (
        <span className="font-mono text-[11px] font-semibold text-ink bg-paper px-2 py-0.5 rounded border border-line whitespace-nowrap">
          {valueText}
        </span>
      ) : passed ? (
        <span className="inline-flex items-center gap-1 text-emerald-700 font-semibold font-mono text-[11px] bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 whitespace-nowrap">
          <Check className="w-3.5 h-3.5 text-emerald-600 stroke-[2.5]" aria-hidden="true" /> Valid
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 text-red-700 font-semibold font-mono text-[11px] bg-red-50 px-2 py-0.5 rounded border border-red-200 whitespace-nowrap">
          <X className="w-3.5 h-3.5 text-red-600 stroke-[2.5]" aria-hidden="true" /> Failed
        </span>
      )}
    </li>
  );
}

export default function SecurityPanel({ checks }) {
  const { certificate = {}, signature = {}, integrity = {} } = checks || {};
  const isCertOk = certificate.status === "VALID";
  const isSigOk = signature.status === "VALID";
  const isIntOk = integrity.status === "PASSED";

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      {/* 1. Certificate Panel */}
      <div
        className={`surface p-5 shadow-card flex flex-col justify-between transition-all duration-200 hover:shadow-card-hover border-t-4 ${
          isCertOk ? "border-t-emerald-500" : "border-t-red-500"
        }`}
      >
        <div>
          <div className="flex items-center justify-between pb-3.5 mb-3.5 border-b border-line">
            <div className="flex items-center gap-2.5">
              <span className="icon-tile w-8 h-8 !rounded-lg shadow-sm">
                <Award className="w-4 h-4 text-lime" aria-hidden="true" />
              </span>
              <h3 className="font-bold text-ink text-sm uppercase tracking-wider font-mono">
                Certificate
              </h3>
            </div>
            <span
              className={`pill ${
                isCertOk ? "pill-ok" : "pill-bad"
              } font-mono text-[11px] font-bold px-2.5 py-0.5`}
            >
              {certificate.status || "UNKNOWN"}
            </span>
          </div>
          <ul className="space-y-0.5">
            <CheckItem label="CipherLock Root CA signature" passed={certificate.ca_signature_ok} />
            <CheckItem label="Validity period (not expired)" passed={certificate.validity_ok} />
            <CheckItem label="Certificate revocation status" passed={certificate.not_revoked} />
            <CheckItem label="Subject matches sender" passed={certificate.subject_ok} />
            <CheckItem label="Key usage (digitalSignature)" passed={certificate.key_usage_ok} />
            <CheckItem label="Serial binding in header" passed={certificate.serial_matches} />
          </ul>
        </div>
      </div>

      {/* 2. Signature Panel */}
      <div
        className={`surface p-5 shadow-card flex flex-col justify-between transition-all duration-200 hover:shadow-card-hover border-t-4 ${
          isSigOk ? "border-t-emerald-500" : "border-t-red-500"
        }`}
      >
        <div>
          <div className="flex items-center justify-between pb-3.5 mb-3.5 border-b border-line">
            <div className="flex items-center gap-2.5">
              <span className="icon-tile w-8 h-8 !rounded-lg shadow-sm">
                <FileCheck className="w-4 h-4 text-lime" aria-hidden="true" />
              </span>
              <h3 className="font-bold text-ink text-sm uppercase tracking-wider font-mono">
                Signature
              </h3>
            </div>
            <span
              className={`pill ${
                isSigOk ? "pill-ok" : "pill-bad"
              } font-mono text-[11px] font-bold px-2.5 py-0.5`}
            >
              {signature.status || "UNKNOWN"}
            </span>
          </div>
          <ul className="space-y-0.5">
            <CheckItem label="RSA-PSS digital signature" passed={signature.signature_ok} />
            <CheckItem label="Algorithm parameters" valueText="SHA-256 / 32B salt" />
            <CheckItem label="Canonical JSON header" passed={signature.canonical_header_ok} />
            <CheckItem
              label="Sender public key certified"
              passed={signature.signature_ok && certificate.ca_signature_ok}
            />
          </ul>
        </div>
      </div>

      {/* 3. Integrity Panel */}
      <div
        className={`surface p-5 shadow-card flex flex-col justify-between transition-all duration-200 hover:shadow-card-hover border-t-4 ${
          isIntOk ? "border-t-emerald-500" : "border-t-red-500"
        }`}
      >
        <div>
          <div className="flex items-center justify-between pb-3.5 mb-3.5 border-b border-line">
            <div className="flex items-center gap-2.5">
              <span className="icon-tile w-8 h-8 !rounded-lg shadow-sm">
                <Shield className="w-4 h-4 text-lime" aria-hidden="true" />
              </span>
              <h3 className="font-bold text-ink text-sm uppercase tracking-wider font-mono">
                Integrity
              </h3>
            </div>
            <span
              className={`pill ${
                isIntOk ? "pill-ok" : "pill-bad"
              } font-mono text-[11px] font-bold px-2.5 py-0.5`}
            >
              {integrity.status || "UNKNOWN"}
            </span>
          </div>
          <ul className="space-y-0.5">
            <CheckItem label="Recomputed ciphertext SHA-256" passed={integrity.hash_matches} />
            <CheckItem label="Disk payload intact" passed={integrity.payload_intact} />
            <CheckItem label="GCM 16-byte auth tag" valueText="Verified on open" />
            <CheckItem label="Hash computation source" valueText="Stored .bin bytes" />
          </ul>
        </div>
      </div>
    </div>
  );
}
