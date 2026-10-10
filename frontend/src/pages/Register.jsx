import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import PasswordInput from "../components/PasswordInput";
import Spinner from "../components/Spinner";
import AuthShell from "../components/AuthShell";
import { Check, X, ShieldCheck, AlertCircle } from "lucide-react";

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [touched, setTouched] = useState({
    name: false,
    email: false,
    password: false,
    confirmPassword: false,
  });

  const [serverErrors, setServerErrors] = useState({});
  const [globalError, setGlobalError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Password rules validation
  const rules = {
    length: formData.password.length >= 10 && formData.password.length <= 128,
    upper: /[A-Z]/.test(formData.password),
    lower: /[a-z]/.test(formData.password),
    digit: /[0-9]/.test(formData.password),
  };

  const rulesPassed = Object.values(rules).filter(Boolean).length;
  const passwordsMatch = Boolean(
    formData.password &&
    formData.confirmPassword &&
    formData.password === formData.confirmPassword
  );

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear field-specific server errors on change
    if (serverErrors[name]) {
      setServerErrors((prev) => ({ ...prev, [name]: "" }));
    }
    if (globalError) {
      setGlobalError("");
    }
  };

  const handleBlur = (field) => {
    setTouched((prev) => ({ ...prev, [field]: true }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setTouched({
      name: true,
      email: true,
      password: true,
      confirmPassword: true,
    });

    if (rulesPassed < 4) {
      return;
    }
    if (formData.password !== formData.confirmPassword) {
      return;
    }

    setIsSubmitting(true);
    setServerErrors({});
    setGlobalError("");

    try {
      await register(formData.name, formData.email, formData.password);
      // Clean form state and redirect to login with success notice
      navigate("/login", {
        state: { notice: "Registration successful! You may now sign in with your credentials." },
      });
    } catch (err) {
      if (err.fieldErrors) {
        setServerErrors(err.fieldErrors);
      }
      setGlobalError(err.userMessage || "Registration failed. Please check the form.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const nameInvalid = Boolean(serverErrors.name || (touched.name && !formData.name.trim()));
  const emailInvalid = Boolean(serverErrors.email || (touched.email && !formData.email.trim()));

  return (
    <AuthShell>
      {/* Header */}
      <div className="mb-8">
        <span className="icon-tile w-12 h-12 mb-5">
          <ShieldCheck className="w-6 h-6" aria-hidden="true" />
        </span>
        <p className="eyebrow text-lime-dark mb-1.5">Secure access</p>
        <h1 className="text-2.5xl sm:text-3xl font-extrabold tracking-tight text-ink">
          Create your account
        </h1>
        <p className="text-sm text-ink-muted mt-2">
          Join CipherLock for secure, recipient-verified file sharing.
        </p>
      </div>

      {globalError && (
        <div role="alert" aria-live="assertive" className="alert alert-error mb-6">
          <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-600" />
          <div className="flex-1 font-medium">{globalError}</div>
        </div>
      )}

      <div className="surface p-6 sm:p-8">
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          {/* Full Name */}
          <div>
            <label htmlFor="register-name" className="field-label">Full Name</label>
            <input
              id="register-name"
              name="name"
              type="text"
              autoComplete="name"
              required
              disabled={isSubmitting}
              value={formData.name}
              onChange={handleChange}
              onBlur={() => handleBlur("name")}
              placeholder="e.g. Siddharth Verma"
              aria-invalid={nameInvalid}
              aria-describedby={serverErrors.name ? "name-error" : undefined}
              className={`form-input ${nameInvalid ? "is-invalid" : ""}`}
            />
            {serverErrors.name && (
              <p id="name-error" className="text-xs text-red-600 mt-1 font-medium">{serverErrors.name}</p>
            )}
          </div>

          {/* Email */}
          <div>
            <label htmlFor="register-email" className="field-label">Email Address</label>
            <input
              id="register-email"
              name="email"
              type="email"
              autoComplete="email"
              required
              disabled={isSubmitting}
              value={formData.email}
              onChange={handleChange}
              onBlur={() => handleBlur("email")}
              placeholder="name@example.com"
              aria-invalid={emailInvalid}
              aria-describedby={serverErrors.email ? "email-error" : undefined}
              className={`form-input ${emailInvalid ? "is-invalid" : ""}`}
            />
            {serverErrors.email && (
              <p id="email-error" className="text-xs text-red-600 mt-1 font-medium">{serverErrors.email}</p>
            )}
          </div>

          {/* Password */}
          <div>
            <label htmlFor="register-password" className="field-label">Password</label>
            <PasswordInput
              id="register-password"
              name="password"
              autoComplete="new-password"
              required
              disabled={isSubmitting}
              value={formData.password}
              onChange={handleChange}
              onBlur={() => handleBlur("password")}
              hasError={Boolean(serverErrors.password || (touched.password && rulesPassed < 4))}
              ariaDescribedBy="password-rules"
            />
            {serverErrors.password && (
              <p className="text-xs text-red-600 mt-1 font-medium">{serverErrors.password}</p>
            )}

            <div className="mt-3 rounded-lg bg-paper border border-line p-3">
              <div className="flex items-center justify-between text-[10.5px] text-ink-muted mb-1.5 font-mono uppercase tracking-wider">
                <span>Strength</span>
                <span>{rulesPassed}/4 requirements</span>
              </div>
              <div className="grid grid-cols-4 gap-1.5 h-1.5">
                {[1, 2, 3, 4].map((step) => (
                  <div
                    key={step}
                    className={`h-full rounded-full transition-colors ${
                      rulesPassed >= step
                        ? step <= 2
                          ? "bg-amber-400"
                          : "bg-emerald-500"
                        : "bg-line-strong/60"
                    }`}
                  />
                ))}
              </div>
              <div id="password-rules" className="mt-3 space-y-1 text-xs text-ink-muted">
                {[
                  [rules.length, "10–128 characters long"],
                  [rules.upper, "At least one uppercase letter (A–Z)"],
                  [rules.lower, "At least one lowercase letter (a–z)"],
                  [rules.digit, "At least one digit (0–9)"],
                ].map(([ok, label]) => (
                  <div key={label} className="flex items-center gap-1.5">
                    {ok ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <X className="w-3.5 h-3.5 text-slate-300" />
                    )}
                    <span className={ok ? "text-ink font-medium" : ""}>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <label htmlFor="register-confirm-password" className="field-label">Confirm Password</label>
            <PasswordInput
              id="register-confirm-password"
              name="confirmPassword"
              autoComplete="new-password"
              required
              disabled={isSubmitting}
              value={formData.confirmPassword}
              onChange={handleChange}
              onBlur={() => handleBlur("confirmPassword")}
              hasError={Boolean(touched.confirmPassword && formData.confirmPassword && !passwordsMatch)}
              ariaDescribedBy="confirm-password-feedback"
            />
            {touched.confirmPassword && formData.confirmPassword && (
              <div id="confirm-password-feedback" className="mt-1.5 text-xs flex items-center gap-1">
                {passwordsMatch ? (
                  <span className="text-emerald-700 flex items-center gap-1 font-medium">
                    <Check className="w-3.5 h-3.5" /> Passwords match
                  </span>
                ) : (
                  <span className="text-red-600 flex items-center gap-1 font-medium">
                    <X className="w-3.5 h-3.5" /> Passwords do not match
                  </span>
                )}
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={isSubmitting || rulesPassed < 4 || (formData.confirmPassword && !passwordsMatch)}
            className="w-full btn-lime py-3 px-4 rounded-lg text-sm"
          >
            {isSubmitting ? (
              <>
                <Spinner size="sm" className="border-navy border-t-transparent" />
                <span>Creating account...</span>
              </>
            ) : (
              <span>Register Account</span>
            )}
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-line text-center text-sm text-ink-muted">
          Already have an account?{" "}
          <Link to="/login" className="font-semibold text-navy hover:text-lime-dark hover:underline">
            Sign in here
          </Link>
        </div>
      </div>
    </AuthShell>
  );
}
