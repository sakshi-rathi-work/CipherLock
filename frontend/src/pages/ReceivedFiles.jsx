// Displays files received by the logged-in user.

import React from "react";
import { Info, Inbox } from "lucide-react";
import TransferList from "../components/TransferList";

export default function ReceivedFiles() {
  return (
    <div className="page max-w-5xl">
      <div className="mb-6">
        <p className="eyebrow text-lime-dark mb-2">Inbox</p>
        <h1 className="page-title">
          <span className="icon-tile w-11 h-11"><Inbox className="w-5 h-5" aria-hidden="true" /></span> Received Files
        </h1>
        <p className="text-sm text-ink-muted mt-2 max-w-2xl">
          Encrypted files that other CipherLock users have sent to you.
        </p>
      </div>
      <div className="alert alert-info mb-6 shadow-card">
        <Info className="w-4 h-4 mt-0.5 text-lime-dark flex-shrink-0" aria-hidden="true" />
        <p>
          Your files are stored encrypted on the server. Signature verification, decryption and download are
          not available yet, so entries show as awaiting verification.
        </p>
      </div>
      <TransferList mode="received" />
    </div>
  );
}
