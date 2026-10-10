// Reusable component for displaying file transfer information.

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Inbox, RefreshCw, Search, Send } from "lucide-react";
import { api } from "../api/client";
import { describeStatus, fileIconFor, formatBytes, formatTimestamp } from "../utils/files";

const PAGE_SIZE = 25;

const TONES = {
  emerald: "pill-ok",
  amber: "pill-warn",
  slate: "pill-neutral",
};

function StatusPill({ status, mode }) {
  const info = describeStatus(status, mode);
  return (
    <span
      title={info.hint}
      className={`pill ${TONES[info.tone]}`}
    >
      {info.label}
    </span>
  );
}

/**
 * Shared, API-backed list for the Sent Files and Received Files pages.
 * mode="sent"     -> GET /api/files/sent     (shows recipient)
 * mode="received" -> GET /api/files/received (shows sender)
 */
export default function TransferList({ mode }) {
  const isSent = mode === "sent";
  const [files, setFiles] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const requestCounter = useRef(0);

  // Debounce the search box so we do not query on every keystroke.
  useEffect(() => {
    const timer = setTimeout(() => setQuery(search.trim()), 300);
    return () => clearTimeout(timer);
  }, [search]);

  const load = useCallback(
    async ({ append = false, offset = 0 } = {}) => {
      const requestId = ++requestCounter.current;
      append ? setLoadingMore(true) : setLoading(true);
      setError("");
      try {
        const res = await api.get(`/files/${mode}`, {
          params: { limit: PAGE_SIZE, offset, ...(query ? { q: query } : {}) },
        });
        if (requestId !== requestCounter.current) return; // stale response
        const page = res.data?.files || [];
        setFiles((prev) => (append ? [...prev, ...page] : page));
        setTotal(res.data?.total ?? page.length);
      } catch (err) {
        if (requestId !== requestCounter.current) return;
        setError(err.userMessage || "Could not load your files.");
      } finally {
        if (requestId === requestCounter.current) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [mode, query]
  );

  useEffect(() => {
    load();
  }, [load]);

  const hasMore = files.length < total;
  const counterpartKey = isSent ? "receiver" : "sender";

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-5">
        <div className="relative flex-1 max-w-md">
          <label htmlFor={`${mode}-search`} className="sr-only">
            Search {isSent ? "sent" : "received"} files
          </label>
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
          <input
            id={`${mode}-search`}
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={isSent ? "Search by filename or recipient" : "Search by filename or sender"}
            className="form-input pl-10"
            maxLength={100}
          />
        </div>
        <p className="text-xs font-mono text-ink-muted sm:ml-auto" aria-live="polite">
          {loading ? "Loading…" : `${total} file${total === 1 ? "" : "s"}${query ? " matching your search" : ""}`}
        </p>
      </div>

      {error && (
        <div role="alert" className="alert alert-error mb-5">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div className="flex-1">
            <p className="font-semibold">Something went wrong</p>
            <p>{error}</p>
          </div>
          <button
            type="button"
            onClick={() => load()}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-white border border-red-200 hover:bg-red-100"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Retry
          </button>
        </div>
      )}

      {loading ? (
        <ul className="surface divide-y divide-line" aria-busy="true">
          {[0, 1, 2].map((n) => (
            <li key={n} className="p-4 flex items-center gap-4 animate-pulse">
              <div className="w-10 h-10 rounded-xl bg-paper-alt" />
              <div className="flex-1 space-y-2">
                <div className="h-3.5 w-1/3 rounded bg-paper-alt" />
                <div className="h-3 w-1/2 rounded bg-paper-alt" />
              </div>
            </li>
          ))}
        </ul>
      ) : files.length === 0 && !error ? (
        <div className="bg-white border-2 border-dashed border-line-strong rounded-2xl p-12 text-center">
          <div className="icon-tile mx-auto w-14 h-14 mb-4">
            {isSent ? <Send className="w-5 h-5" aria-hidden="true" /> : <Inbox className="w-5 h-5" aria-hidden="true" />}
          </div>
          {query ? (
            <>
              <p className="font-semibold text-ink">No files match “{query}”</p>
              <p className="text-sm text-ink-muted mt-1">Try a different filename or name.</p>
            </>
          ) : isSent ? (
            <>
              <p className="font-semibold text-ink">You haven’t sent any files yet</p>
              <p className="text-sm text-ink-muted mt-1 mb-4">Files you send are encrypted and signed before they are stored.</p>
              <Link to="/send" className="btn-lime px-5 py-2.5 rounded-lg text-sm">
                Send your first file
              </Link>
            </>
          ) : (
            <>
              <p className="font-semibold text-ink">Nothing received yet</p>
              <p className="text-sm text-ink-muted mt-1">Files that other users send to you will appear here.</p>
            </>
          )}
        </div>
      ) : (
        <>
          <ul className="surface divide-y divide-line overflow-hidden">
            {files.map((item) => {
              const Icon = fileIconFor(item.original_filename);
              const person = item[counterpartKey];
              return (
                <li key={item.id} className="p-4 sm:px-5 flex flex-wrap items-center gap-x-4 gap-y-2 transition-colors hover:bg-paper/70">
                  <div className="icon-tile w-10 h-10" aria-hidden="true">
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="min-w-0 flex-1 basis-56">
                    <p className="font-semibold text-ink truncate" title={item.original_filename}>
                      {item.original_filename}
                    </p>
                    <p className="text-xs text-ink-muted truncate">
                      {isSent ? "To" : "From"} <span className="font-medium text-ink">{person?.name}</span>
                      <span className="font-mono"> · {person?.email}</span>
                    </p>
                  </div>
                  <div className="text-xs text-ink-muted sm:text-right">
                    <p>{formatTimestamp(item.created_at)}</p>
                    <p className="font-mono">{formatBytes(item.size_bytes)}</p>
                  </div>
                  <div className="sm:w-44 sm:text-right">
                    <StatusPill status={item.status} mode={mode} />
                  </div>
                </li>
              );
            })}
          </ul>
          {hasMore && (
            <div className="mt-5 text-center">
              <button
                type="button"
                onClick={() => load({ append: true, offset: files.length })}
                disabled={loadingMore}
                className="btn-secondary"
              >
                {loadingMore ? "Loading…" : `Load more (${total - files.length} remaining)`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
