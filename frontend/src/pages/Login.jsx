import React, { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import PasswordInput from "../components/PasswordInput";
import Spinner from "../components/Spinner";
import AuthShell from "../components/AuthShell";
import { Lock, AlertCircle, Clock, CheckCircle2 } from "lucide-react";

export default function Login() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(location.state?.notice || "");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);

  // If already authenticated, redirect to dashboard
  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard", { replace: true });
    }
  }, [isAuthenticated, navigate]);

  // Lockout countdown timer
  useEffect(() => {
    if (lockoutSeconds <= 0) return;
    const interval = setInterval(() => {
      setLockoutSeconds((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          setError(""); // Clear lockout error when timer expires
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [lockoutSeconds]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (lockoutSeconds > 0) return;

    setError("");
    setNotice("");
    setIsSubmitting(true);

    try {
      await login(email, password);
      // Safe internal redirect (P14)
      const from = location.state?.from?.pathname;
      const destination =
        from && from.startsWith("/") && !from.startsWith("//")
          ? from
          : "/dashboard";
      navigate(destination, { replace: true });
    } catch (err) {
      if (err.response?.status === 429 && err.retryAfter) {
        setLockoutSeconds(Number(err.retryAfter));
        setError(
          `Too many failed login attempts. Your account or IP is temporarily locked out.`
        );
      } else {
        setError(err.userMessage || "Invalid email or password");
      }
    } finally {
      setIsSubmitting(false);
      // Clear password field from state after submit for security
      setPassword("");
    }
  };

  return (
    <AuthShell>
      {/* Header */}
      <div className="mb-8">
        <span className="icon-tile w-12 h-12 mb-5">
          <Lock className="w-6 h-6" aria-hidden="true" />
        </span>
        <p className="eyebrow text-lime-dark mb-1.5">Welcome back</p>
        <h1 className="text-2.5xl sm:text-3xl font-extrabold tracking-tight text-ink">
          Sign in to CipherLock
        </h1>
        <p className="text-sm text-ink-muted mt-2">
          Enter your credentials to access your secure workspace.
        </p>
      </div>

      {/* Informational Notice (e.g. registered or signed out) */}
      {notice && (
        <div role="status" className="alert alert-success mb-6">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0 mt-0.5 text-emerald-600" />
          <div className="flex-1 font-medium">{notice}</div>
        </div>
      )}

      {/* Error / Lockout Banner */}
      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className={`alert mb-6 ${lockoutSeconds > 0 ? "alert-warn" : "alert-error"}`}
        >
          {lockoutSeconds > 0 ? (
            <Clock className="w-5 h-5 flex-shrink-0 mt-0.5 text-amber-600" />
          ) : (
            <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-600" />
          )}
          <div className="flex-1">
            <div className="font-medium">{error}</div>
            {lockoutSeconds > 0 && (
              <div className="mt-1 text-xs font-mono font-semibold text-amber-800">
                Please try again in {lockoutSeconds} second
                {lockoutSeconds !== 1 ? "s" : ""}.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Card */}
      <div className="surface p-6 sm:p-8">
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          <div>
            <label htmlFor="login-email" className="field-label">Email Address</label>
            <input
              id="login-email"
              name="email"
              type="email"
              autoComplete="email"
              required
              disabled={isSubmitting || lockoutSeconds > 0}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="name@example.com"
              className="form-input"
            />
          </div>

          <div>
            <label htmlFor="login-password" className="field-label">Password</label>
            <PasswordInput
              id="login-password"
              name="password"
              autoComplete="current-password"
              required
              disabled={isSubmitting || lockoutSeconds > 0}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <button
            type="submit"
            disabled={isSubmitting || lockoutSeconds > 0 || !email || !password}
            className="w-full btn-lime py-3 px-4 rounded-lg text-sm"
          >
            {isSubmitting ? (
              <>
                <Spinner size="sm" className="border-navy border-t-transparent" />
                <span>Signing in...</span>
              </>
            ) : lockoutSeconds > 0 ? (
              <span>Locked ({lockoutSeconds}s)</span>
            ) : (
              <span>Sign In</span>
            )}
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-line text-center text-sm text-ink-muted">
          Don't have an account yet?{" "}
          <Link to="/register" className="font-semibold text-navy hover:text-lime-dark hover:underline">
            Create an account
          </Link>
        </div>
      </div>
    </AuthShell>
  );
}
