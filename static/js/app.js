/**
 * CipherLock Phase 8 Application Script
 *
 * Responsibilities:
 * - Password visibility toggle for decryption authentication
 * - Form submit loading spinners (prevent duplicate submissions during RSA/AES operations)
 * - Confirmation dialog handlers for security-sensitive actions
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // 1. Password reveal toggle
  const toggleBtn = document.getElementById("togglePasswordBtn");
  const passwordInput = document.getElementById("passwordInput");

  if (toggleBtn && passwordInput) {
    toggleBtn.addEventListener("click", () => {
      const isPassword = passwordInput.getAttribute("type") === "password";
      passwordInput.setAttribute("type", isPassword ? "text" : "password");
      toggleBtn.textContent = isPassword ? "🔒" : "👁";
      toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
    });
  }

  // 2. Loading spinners on form submission (e.g. Decrypt & Download)
  const decryptForm = document.getElementById("decryptForm");
  const downloadSubmitBtn = document.getElementById("downloadSubmitBtn");

  if (decryptForm && downloadSubmitBtn) {
    decryptForm.addEventListener("submit", (e) => {
      // If form valid, show spinner and disable button to prevent double-clicks
      if (decryptForm.checkValidity()) {
        const originalContent = downloadSubmitBtn.innerHTML;
        downloadSubmitBtn.disabled = true;
        downloadSubmitBtn.innerHTML = `
          <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
          <span>Decrypting & Streaming...</span>
        `;

        // Re-enable after short delay in case browser initiates file download without reloading page
        setTimeout(() => {
          downloadSubmitBtn.disabled = false;
          downloadSubmitBtn.innerHTML = originalContent;
        }, 5000);
      }
    });
  }

  // 3. Confirm dialogs for sensitive actions
  document.querySelectorAll("[data-confirm]").forEach((element) => {
    element.addEventListener("click", (event) => {
      const message = element.getAttribute("data-confirm") || "Are you sure you want to proceed?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
});
