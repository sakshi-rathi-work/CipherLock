import React, { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

export default function PasswordInput({
  id,
  name,
  value,
  onChange,
  onBlur,
  placeholder = "••••••••••••",
  autoComplete = "current-password",
  required = false,
  hasError = false,
  ariaDescribedBy,
  disabled = false,
  className = "",
}) {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="relative">
      <input
        id={id}
        name={name}
        type={showPassword ? "text" : "password"}
        value={value}
        onChange={onChange}
        onBlur={onBlur}
        placeholder={placeholder}
        autoComplete={autoComplete}
        required={required}
        disabled={disabled}
        aria-invalid={hasError}
        aria-describedby={ariaDescribedBy}
        className={`form-input pr-10 ${hasError ? "is-invalid" : ""} ${className}`}
      />
      <button
        type="button"
        tabIndex={0}
        onClick={() => setShowPassword(!showPassword)}
        aria-label={showPassword ? "Hide password" : "Show password"}
        aria-pressed={showPassword}
        className="absolute inset-y-0 right-0 pr-3 flex items-center text-ink-muted hover:text-ink focus:outline-none focus-visible:text-ink"
      >
        {showPassword ? (
          <EyeOff className="w-4 h-4 text-[#738194]" aria-hidden="true" />
        ) : (
          <Eye className="w-4 h-4 text-[#738194]" aria-hidden="true" />
        )}
      </button>
    </div>
  );
}
