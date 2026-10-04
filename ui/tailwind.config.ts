import type { Config } from "tailwindcss";

const c = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: c("bg"),
        panel: c("panel"),
        raised: c("raised"),
        well: c("well"),
        line: c("line"),
        "line-strong": c("line-strong"),
        ink: c("ink"),
        "ink-2": c("ink-2"),
        "ink-3": c("ink-3"),
        signal: c("signal"),
        parsed: c("parsed"),
        partial: c("partial"),
        unparsed: c("unparsed"),
        info: c("info")
      },
      fontFamily: {
        display: ["Fraunces", "Georgia", "serif"],
        sans: ['"Instrument Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"]
      },
      fontSize: { "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.02em" }] },
      keyframes: {
        rise: { from: { opacity: "0", transform: "translateY(8px)" }, to: { opacity: "1", transform: "none" } },
        pulseDot: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.35" } },
        sweep: { from: { backgroundPosition: "-200% 0" }, to: { backgroundPosition: "200% 0" } },
        flash: { from: { backgroundColor: "rgb(var(--signal) / 0.18)" }, to: { backgroundColor: "transparent" } }
      },
      animation: {
        rise: "rise .5s cubic-bezier(.2,.7,.2,1) both",
        pulseDot: "pulseDot 1.6s ease-in-out infinite",
        sweep: "sweep 1.8s linear infinite",
        flash: "flash 1.2s ease-out both"
      }
    }
  },
  plugins: []
} satisfies Config;
