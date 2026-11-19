/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cobalt: "#00B84C",      // Primary terminal green (replaces blue)
        "acid-dark": "#008A38", // Darker green for hover/borders
        "acid-glow": "#00FF66", // Neon accent on dark blocks
        paper: "#F4F7F4",       // Slight green-tinted crisp graph paper
        ink: "#0A0A0A",
      },
      fontFamily: {
        pixel: ['"Silkscreen"', "monospace"],
        mono: ['"JetBrains Mono"', "monospace"],
      },
      boxShadow: {
        pixel: "4px 4px 0px #0A0A0A",
        "pixel-sm": "2px 2px 0px #0A0A0A",
        "pixel-green": "5px 5px 0px #00B84C",
      },
    },
  },
  plugins: [],
};