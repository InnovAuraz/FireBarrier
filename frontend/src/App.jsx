import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import BlockedIPs from './pages/BlockedIPs'
import Analytics from './pages/Analytics'

function App() {
  return (
    <Router>
      <div className="flex min-h-screen bg-cyber-dark">
        <Sidebar />
        
        <main className="flex-1 lg:ml-64 md:ml-20 ml-20 transition-all duration-300">
          <AnimatePresence mode="wait">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/threats" element={<Threats />} />
              <Route path="/blocked-ips" element={<BlockedIPs />} />
              <Route path="/analytics" element={<Analytics />} />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    </Router>
  )
}

export default App
