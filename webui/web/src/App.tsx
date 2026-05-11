import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Sidebar } from '@/components/Sidebar'
import { Dashboard } from '@/pages/Dashboard'
import { Config } from '@/pages/Config'
import { Exclusions } from '@/pages/Exclusions'
import { DNS } from '@/pages/DNS'
import { Logs } from '@/pages/Logs'

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1 } } })

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/config" element={<Config />} />
              <Route path="/exclusions" element={<Exclusions />} />
              <Route path="/dns" element={<DNS />} />
              <Route path="/logs" element={<Logs />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
