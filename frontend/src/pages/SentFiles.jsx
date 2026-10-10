// Displays files sent by the logged-in user.

import React from "react";
import { Link } from "react-router-dom";
import { Send } from "lucide-react";
import TransferList from "../components/TransferList";

export default function SentFiles() {
  return (
    <div className="page max-w-5xl">
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow text-lime-dark mb-2">Outbox</p>
          <h1 className="page-title">
            <span className="icon-tile w-11 h-11"><Send className="w-5 h-5" aria-hidden="true" /></span> Sent Files
          </h1>
          <p className="text-sm text-ink-muted mt-2 max-w-2xl">
            Files you have encrypted and shared. Only you and the recipient can see these entries, and only
            the recipient’s private key can ever decrypt the contents.
          </p>
        </div>
        <Link to="/send" className="btn-lime px-5 py-2.5 rounded-lg text-sm">
          Send a file
        </Link>
      </div>
      <TransferList mode="sent" />
    </div>
  );
}
