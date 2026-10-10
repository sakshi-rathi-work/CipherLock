import React from "react";

export default function Spinner({ size = "md", className = "" }) {
  const sizeClasses = {
    sm: "w-4 h-4 border-2",
    md: "w-6 h-6 border-2",
    lg: "w-8 h-8 border-[3px]",
  };

  return (
    <div
      role="status"
      aria-label="Loading"
      className={`inline-block animate-spin rounded-full border-navy border-t-transparent ${sizeClasses[size] || sizeClasses.md} ${className}`}
    >
      <span className="sr-only">Loading...</span>
    </div>
  );
}
