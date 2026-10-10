// Shared helpers for the file-sharing pages (Phase 7).
import {
  File,
  FileArchive,
  FileAudio,
  FileCode,
  FileImage,
  FileSpreadsheet,
  FileText,
  FileVideo,
} from "lucide-react";

// Usability-only limit; the backend (25 MiB) is authoritative.
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatTimestamp(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const EXTENSION_ICONS = {
  FileText: ["txt", "md", "pdf", "doc", "docx", "rtf", "odt"],
  FileSpreadsheet: ["xls", "xlsx", "csv", "ods"],
  FileImage: ["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"],
  FileArchive: ["zip", "tar", "gz", "7z", "rar", "bz2"],
  FileAudio: ["mp3", "wav", "ogg", "flac", "m4a"],
  FileVideo: ["mp4", "mov", "avi", "mkv", "webm"],
  FileCode: ["js", "jsx", "ts", "tsx", "py", "java", "c", "cpp", "html", "css", "json", "xml", "sql", "sh"],
};
const ICON_COMPONENTS = { FileText, FileSpreadsheet, FileImage, FileArchive, FileAudio, FileVideo, FileCode };

export function fileIconFor(filename = "") {
  const ext = filename.includes(".") ? filename.split(".").pop().toLowerCase() : "";
  const match = Object.entries(EXTENSION_ICONS).find(([, list]) => list.includes(ext));
  return match ? ICON_COMPONENTS[match[0]] : File;
}

// Delivery status as stored by the backend ("pending" is the only Phase 7 value).
export function describeStatus(status, mode) {
  if (status === "pending") {
    return mode === "received"
      ? { label: "Awaiting verification", tone: "amber", hint: "Stored encrypted. Verification and decryption are not available yet." }
      : { label: "Delivered", tone: "emerald", hint: "Encrypted, signed and stored for the recipient. Not yet verified by them." };
  }
  const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : "Unknown";
  return { label, tone: "slate", hint: "" };
}

export function newRequestId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Fallback: matches the backend's ^[A-Za-z0-9_-]{8,64}$ rule.
  return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}
