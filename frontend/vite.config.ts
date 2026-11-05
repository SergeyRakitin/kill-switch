import { defineConfig } from 'vite'
import tailwind from '@tailwindcss/vite'

export default defineConfig({ base: './', plugins: [tailwind()] })
