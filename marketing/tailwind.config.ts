import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0B0D10",
        panel: "#13161B",
        "fg-primary": "#F2F4F7",
        "fg-muted": "#9BA1AA",
        "fg-subtle": "#6B7079",
        accent: "#5B8DEF",
        "accent-bright": "#7AA8FF",
        border: "#22262C",
      },
      fontFamily: {
        sans: ['"Inter"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      maxWidth: {
        prose: "72ch",
      },
    },
  },
  plugins: [],
};

export default config;
