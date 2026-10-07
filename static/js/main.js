/**
 * CipherLock – landing page interactions.
 *
 * Responsibilities kept intentionally narrow for Phase 1:
 *  1. Smooth-scroll polyfill for browsers that lack native support.
 *  2. Navbar elevation on scroll (adds a subtle shadow when the user
 *     has scrolled past the hero section).
 *  3. Intersection-Observer–driven entrance animations for feature cards
 *     and section headings (no layout shift, degrades gracefully).
 *  4. Accessible "skip to content" keyboard shortcut.
 *
 * No framework dependencies – plain ES2020 that is understood by every
 * modern browser without a build step.
 */

"use strict";

/* ── 1. Smooth-scroll for anchor links ─────────────────────────────── */
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", (event) => {
    const target = document.querySelector(anchor.getAttribute("href"));
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: "smooth", block: "start" });
    /* Move focus to the target so screen readers announce the destination. */
    target.setAttribute("tabindex", "-1");
    target.focus({ preventScroll: true });
  });
});

/* ── 2. Navbar elevation on scroll ─────────────────────────────────── */
(function initNavElevation() {
  const nav = document.querySelector(".site-nav");
  if (!nav) return;

  const SCROLL_THRESHOLD = 60; /* px */

  function updateNav() {
    nav.classList.toggle("site-nav--elevated", window.scrollY > SCROLL_THRESHOLD);
  }

  window.addEventListener("scroll", updateNav, { passive: true });
  updateNav(); /* run once in case the page loads mid-scroll */
})();

/* ── 3. Entrance animations via IntersectionObserver ───────────────── */
(function initEntranceAnimations() {
  if (!("IntersectionObserver" in window)) return; /* graceful degradation */

  const ANIMATE_SELECTOR = ".feature-card, .section-heading, .intro-band";
  const ANIMATE_CLASS = "is-visible";

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add(ANIMATE_CLASS);
          observer.unobserve(entry.target); /* animate once */
        }
      });
    },
    { threshold: 0.12 }
  );

  document.querySelectorAll(ANIMATE_SELECTOR).forEach((el) => {
    el.classList.add("will-animate");
    observer.observe(el);
  });
})();

/* ── 4. Keyboard "skip to content" ─────────────────────────────────── */
(function initSkipLink() {
  const skipLink = document.getElementById("skip-to-content");
  if (!skipLink) return;

  skipLink.addEventListener("click", (event) => {
    const main = document.querySelector("main");
    if (!main) return;
    event.preventDefault();
    main.setAttribute("tabindex", "-1");
    main.focus({ preventScroll: false });
  });
})();
