/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#020617", // OLED midnight
        card: "#0b0f19",       // Deep Slate
        primary: "#1e293b",    // Steel Grey
        accent: "#22c55e",     // Cyber Green
        warning: "#eab308",    // Alert Yellow
        danger: "#ef4444",     // Critical Red
        border: "#1e293b"      // Card divider grey
      },
      fontFamily: {
        mono: ['Fira Code', 'monospace'],
        sans: ['Fira Sans', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
