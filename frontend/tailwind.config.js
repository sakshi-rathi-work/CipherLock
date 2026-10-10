/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: "#0b1b2e",
          deep: "#07121f",
          surface: "#12283f",
          panel: "#0f2237",
          border: "#2a4560",
          soft: "#1b3550",
        },
        ink: {
          DEFAULT: "#13243a",
          muted: "#64748b",
          light: "#aebdca",
        },
        lime: {
          DEFAULT: "#c4f16e",
          hover: "#d4f98c",
          dark: "#4f7a1c",
          muted: "#849272",
          tint: "#f3fbe1",
        },
        paper: {
          DEFAULT: "#f4f6f9",
          alt: "#e8edf3",
        },
        line: {
          DEFAULT: "#e2e8f0",
          strong: "#cbd5e1",
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      fontSize: {
        "2.5xl": ["1.75rem", { lineHeight: "2.1rem" }],
      },
      boxShadow: {
        card: "0 1px 2px rgba(11,27,46,0.04), 0 10px 28px -12px rgba(11,27,46,0.14)",
        "card-hover": "0 2px 4px rgba(11,27,46,0.05), 0 18px 40px -14px rgba(11,27,46,0.22)",
        panel: "0 24px 60px -20px rgba(7,18,31,0.55)",
        nav: "0 1px 0 rgba(255,255,255,0.04), 0 8px 24px -8px rgba(0,0,0,0.4)",
        lime: "0 0 0 1px rgba(196,241,110,0.35), 0 8px 24px -6px rgba(196,241,110,0.35)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.45s ease-out both",
        "fade-in": "fade-in 0.35s ease-out both",
      },
    },
  },
  plugins: [],
};
