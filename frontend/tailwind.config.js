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
          DEFAULT: "#0c1d31",
          deep: "#091728",
          surface: "#132b45",
          panel: "#10243a",
          border: "#56708760",
        },
        ink: {
          DEFAULT: "#17283c",
          muted: "#738194",
          light: "#aebdca",
        },
        lime: {
          DEFAULT: "#c4f16e",
          hover: "#d2fa87",
          dark: "#789b4d",
          muted: "#849272",
        },
        paper: {
          DEFAULT: "#f5f7f8",
          alt: "#e9eef1",
        },
        line: {
          DEFAULT: "#dce3e9",
        },
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: "0 14px 30px #1b344111",
        panel: "0 22px 60px #0000004d",
        nav: "0 4px 20px rgba(0, 0, 0, 0.35)",
        lime: "0 0 20px rgba(196, 241, 110, 0.25)",
      },
    },
  },
  plugins: [],
};
