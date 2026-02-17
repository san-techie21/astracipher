/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f7ff',
          100: '#e0efff',
          200: '#b9dfff',
          300: '#7cc4ff',
          400: '#36a5ff',
          500: '#0c87f2',
          600: '#006acf',
          700: '#0054a7',
          800: '#04478a',
          900: '#0a3c72',
          950: '#06264c',
        },
      },
    },
  },
  plugins: [],
};
