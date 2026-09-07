import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

// ── Bootstrap theme before first paint (prevents FOUC) ───────────────────────
;(function () {
  try {
    const stored = JSON.parse(localStorage.getItem('agcms-theme') ?? '{}')
    const theme: string = stored?.state?.theme ?? 'dark'
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light')
      document.documentElement.style.colorScheme = 'light'
    }
  } catch {
    // ignore — stay dark
  }
})()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)

