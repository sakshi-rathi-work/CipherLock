import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import PasswordInput from "../components/PasswordInput";
import Spinner from "../components/Spinner";
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

  return (
    <div className="flex-1 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-navy text-lime mb-3 shadow-md">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <p className="eyebrow text-lime-dark mb-1">SECURE ACCESS</p>
          <h1 className="text-2.5xl font-bold tracking-tight text-ink">
            Create your account
          </h1>
          <p className="text-sm text-ink-muted mt-1.5">
            Join CipherLock for secure, recipient-verified file sharing.
          </p>
        </div>

        {/* Global Error Banner */}
        {globalError && (
          <div
            role="alert"
            aria-live="assertive"
            className="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-start space-x-2.5"
          >
            <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-600" />
            <div className="flex-1 font-medium">{globalError}</div>
          </div>
        )}

        {/* Card */}
        <div className="bg-white rounded-xl border border-line p-6 sm:p-8 shadow-card">
          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            {/* Full Name */}
            <div>
              <label
                htmlFor="register-name"
                className="block text-xs font-semibold uppercase tracking-wider text-ink mb-1.5"
              >
                Full Name
              </label>
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
                aria-invalid={Boolean(serverErrors.name || (touched.name && !formData.name.trim()))}
                aria-describedby={serverErrors.name ? "name-error" : undefined}
                className={`form-input ${
                  serverErrors.name || (touched.name && !formData.name.trim())
                    ? "is-invalid"
                    : ""
                }`}
              />
              {serverErrors.name && (
                <p id="name-error" className="text-xs text-red-600 mt-1 font-medium">
                  {serverErrors.name}
                </p>
              )}
            </div>

            {/* Email Address */}
            <div>
              <label
                htmlFor="register-email"
                className="block text-xs font-semibold uppercase tracking-wider text-ink mb-1.5"
              >
                Email Address
              </label>
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
                aria-invalid={Boolean(serverErrors.email || (touched.email && !formData.email.trim()))}
                aria-describedby={serverErrors.email ? "email-error" : undefined}
                className={`form-input ${
                  serverErrors.email || (touched.email && !formData.email.trim())
                    ? "is-invalid"
                    : ""
                }`}
              />
              {serverErrors.email && (
                <p id="email-error" className="text-xs text-red-600 mt-1 font-medium">
                  {serverErrors.email}
                </p>
              )}
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="register-password"
                className="block text-xs font-semibold uppercase tracking-wider text-ink mb-1.5"
              >
                Password
              </label>
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
                <p className="text-xs text-red-600 mt-1 font-medium">
                  {serverErrors.password}
                </p>
              )}

              {/* Password Strength Indicator */}
              <div className="mt-3">
                <div className="flex items-center justify-between text-xs text-ink-muted mb-1 font-mono">
                  <span>STRENGTH</span>
                  <span>{rulesPassed}/4 REQUIREMENTS</span>
                </div>
                <div className="grid grid-cols-4 gap-1.5 h-1.5">
                  {[1, 2, 3, 4].map((step) => (
                    <div
                      key={step}
                      className={`h-full rounded-full transition-colors ${
                        rulesPassed >= step
                          ? step <= 2
                            ? "bg-amber-400"
                            : "bg-lime-dark"
                          : "bg-line"
                      }`}
                    />
                  ))}
                </div>

                {/* Password Rules Checklist */}
                <div id="password-rules" className="mt-3 space-y-1 text-xs text-ink-muted">
                  <div className="flex items-center space-x-1.5">
                    {rules.length ? (
                      <Check className="w-3.5 h-3.5 text-lime-dark" />
                    ) : (
                      <X className="w-3.5 h-3.5 text-ink-muted opacity-60" />
                    )}
                    <span className={rules.length ? "text-ink font-medium" : ""}>
                      10–128 characters long
                    </span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    {rules.upper ? (
                      <Check className="w-3.5 h-3.5 text-lime-dark" />
                    ) : (
                      <X className="w-3.5 h-3.5 text-ink-muted opacity-60" />
                    )}
                    <span className={rules.upper ? "text-ink font-medium" : ""}>
                      At least one uppercase letter (A–Z)
                    </span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    {rules.lower ? (
                      <Check className="w-3.5 h-3.5 text-lime-dark" />
                    ) : (
                      <X className="w-3.5 h-3.5 text-ink-muted opacity-60" />
                    )}
                    <span className={rules.lower ? "text-ink font-medium" : ""}>
                      At least one lowercase letter (a–z)
                    </span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    {rules.digit ? (
                      <Check className="w-3.5 h-3.5 text-lime-dark" />
                    ) : (
                      <X className="w-3.5 h-3.5 text-ink-muted opacity-60" />
                    )}
                    <span className={rules.digit ? "text-ink font-medium" : ""}>
                      At least one digit (0–9)
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label
                htmlFor="register-confirm-password"
                className="block text-xs font-semibold uppercase tracking-wider text-ink mb-1.5"
              >
                Confirm Password
              </label>
              <PasswordInput
                id="register-confirm-password"
                name="confirmPassword"
                autoComplete="new-password"
                required
                disabled={isSubmitting}
                value={formData.confirmPassword}
                onChange={handleChange}
                onBlur={() => handleBlur("confirmPassword")}
                hasError={Boolean(
                  touched.confirmPassword &&
                  formData.confirmPassword &&
                  !passwordsMatch
                )}
                ariaDescribedBy="confirm-password-feedback"
              />
              {touched.confirmPassword && formData.confirmPassword && (
                <div id="confirm-password-feedback" className="mt-1.5 text-xs flex items-center space-x-1">
                  {passwordsMatch ? (
                    <span className="text-emerald-700 flex items-center space-x-1 font-medium">
                      <Check className="w-3.5 h-3.5" />
                      <span>Passwords match</span>
                    </span>
                  ) : (
                    <span className="text-red-600 flex items-center space-x-1 font-medium">
                      <X className="w-3.5 h-3.5" />
                      <span>Passwords do not match</span>
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting || rulesPassed < 4 || (formData.confirmPassword && !passwordsMatch)}
                className="w-full btn-lime py-2.5 px-4 rounded-lg font-bold text-sm flex items-center justify-center space-x-2 shadow-sm"
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
            </div>
          </form>

          {/* Card Footer */}
          <div className="mt-6 pt-5 border-t border-line text-center text-xs text-ink-muted">
            Already have an account?{" "}
            <Link to="/login" className="font-semibold text-navy hover:underline">
              Sign in here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
