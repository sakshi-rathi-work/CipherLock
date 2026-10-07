/**
 * Secure Axios client with automatic CSRF management and error normalisation.
 *
 * Implements:
 * - withCredentials: true (cookies sent for session auth)
 * - CSRF token caching via GET /api/csrf-token (bare axios request to avoid interceptor recursion)
 * - X-CSRFToken header injection on state-mutating requests (POST, PUT, PATCH, DELETE)
 * - Invalidation and refetching on login/logout/register (P8)
 * - Single automatic retry on CSRF 400 errors
 * - Global unauthenticated event bus for 401 response handling
 * - Strict confidentiality: no passwords, tokens, or request bodies are logged
 */
import axios from "axios";

let cachedCsrfToken = null;
let isFetchingCsrf = null;

// Event listeners for global auth lifecycle events
const unauthenticatedListeners = new Set();

export function onUnauthenticated(callback) {
  unauthenticatedListeners.add(callback);
  return () => unauthenticatedListeners.delete(callback);
}

function notifyUnauthenticated() {
  unauthenticatedListeners.forEach((fn) => {
    try {
      fn();
    } catch (e) {
      // ignore
    }
  });
}

export async function fetchCsrfToken(force = false) {
  if (cachedCsrfToken && !force) {
    return cachedCsrfToken;
  }
  if (isFetchingCsrf) {
    return isFetchingCsrf;
  }

  isFetchingCsrf = axios
    .get("/api/csrf-token", {
      withCredentials: true,
      headers: { "Cache-Control": "no-cache" },
    })
    .then((res) => {
      cachedCsrfToken = res.data?.csrf_token;
      return cachedCsrfToken;
    })
    .catch((err) => {
      cachedCsrfToken = null;
      throw err;
    })
    .finally(() => {
      isFetchingCsrf = null;
    });

  return isFetchingCsrf;
}

export function clearCsrfToken() {
  cachedCsrfToken = null;
}

export const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor: attach CSRF token to mutating requests
api.interceptors.request.use(async (config) => {
  const method = config.method?.toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    try {
      const token = await fetchCsrfToken();
      if (token) {
        config.headers["X-CSRFToken"] = token;
      }
    } catch {
      // Proceed; backend will reject if token is absent/invalid
    }
  }
  return config;
});

// Response interceptor: handle 400 CSRF retry and 401 unauthenticated
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const status = error.response?.status;
    const data = error.response?.data;

    // Retry once if CSRF error occurred
    if (
      status === 400 &&
      !originalRequest._retryCsrf &&
      typeof data?.error === "string" &&
      data.error.toLowerCase().includes("csrf")
    ) {
      originalRequest._retryCsrf = true;
      try {
        const freshToken = await fetchCsrfToken(true);
        if (freshToken) {
          originalRequest.headers["X-CSRFToken"] = freshToken;
          return api(originalRequest);
        }
      } catch {
        // Retry failed
      }
    }

    // Emit unauthenticated event if 401 occurs outside login attempts
    if (status === 401 && !originalRequest.url?.includes("/auth/login")) {
      notifyUnauthenticated();
    }

    // Normalise error response payload for clean UI consumption
    const userMessage =
      data?.error ||
      data?.message ||
      (status === 429
        ? "Too many failed attempts. Please try again later."
        : "An unexpected error occurred. Please try again.");

    error.userMessage = userMessage;
    error.fieldErrors = data?.fields || null;
    error.retryAfter = data?.retry_after || null;

    return Promise.reject(error);
  }
);
