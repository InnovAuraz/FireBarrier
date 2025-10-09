import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { NavLink } from 'react-router-dom'
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Ban, 
  BarChart3, 
  Shield,
  Activity,
  Brain,
  Menu,
  X
} from 'lucide-react'
import { cn } from '../utils/cn'

const Sidebar = () => {
  const [stats, setStats] = useState({
    status: 'connecting...',
    ml_trained: false
  })
  const [isOpen, setIsOpen] = useState(false)
  const [isDesktop, setIsDesktop] = useState(false)
  const [isCollapsed, setIsCollapsed] = useState(false)

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/stats')
        const data = await response.json()
        setStats(data)
      } catch (error) {
        console.error('Backend not connected')
      }
    }

    fetchStats()
    const interval = setInterval(fetchStats, 2000)
    return () => clearInterval(interval)
  }, [])

  // Handle responsive behavior
  useEffect(() => {
    const handleResize = () => {
      const desktop = window.innerWidth >= 1024
      const tablet = window.innerWidth >= 640 && window.innerWidth < 1024
      const mobile = window.innerWidth < 640
      setIsDesktop(desktop)
      
      if (mobile) {
        setIsCollapsed(true) // Mobile - always collapsed (80px)
        setIsOpen(true) // Always visible but tiny
      } else if (tablet) {
        setIsCollapsed(true) // Start collapsed on tablet (80px)
        setIsOpen(true)
      } else {
        setIsCollapsed(false) // Desktop - always expanded (256px)
        setIsOpen(true)
      }
    }
    
    handleResize() // Initial check
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Threats', path: '/threats', icon: AlertTriangle },
    { name: 'Blocked IPs', path: '/blocked-ips', icon: Ban },
    { name: 'Analytics', path: '/analytics', icon: BarChart3 }
  ]

  return (
    <>

      <motion.div
        initial={{ x: -300 }}
        animate={{ 
          x: 0,
          width: isCollapsed ? 80 : 256
        }}
        transition={{ 
          type: "spring", 
          stiffness: 400, 
          damping: 40,
          duration: 0.3
        }}
        className="fixed left-0 top-0 bg-gradient-to-b from-slate-950 to-slate-900 border-r border-slate-800 flex flex-col z-50"
        style={{ 
          position: 'fixed',
          width: window.innerWidth >= 1024 ? 256 : (window.innerWidth < 640 ? 80 : (isCollapsed ? 80 : 256)),
          height: '100vh',
          minHeight: '100vh',
          maxHeight: '100vh',
          top: 0,
          bottom: 0,
          overflowY: 'auto',
          overflowX: 'hidden'
        }}
      >
      {/* Logo */}
      <div className={cn(
        "border-b border-slate-800 flex items-center justify-center",
        window.innerWidth < 640 ? "p-3" : (isCollapsed ? "p-4" : "p-6")
      )}>
        <div className="flex items-center justify-center w-full">
          <div className="flex items-center gap-3">
            <div className={cn(
              "rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center",
              window.innerWidth < 640 ? "w-10 h-10" : "w-10 h-10"
            )}>
              <Shield className={cn(
                "text-white",
                window.innerWidth < 640 ? "w-5 h-5" : "w-6 h-6"
              )} />
            </div>
            {(window.innerWidth >= 1024 || (!isCollapsed && window.innerWidth >= 640)) && (
              <div>
                <h2 className="text-xl font-bold text-cyber-blue">AI-NGFW</h2>
                <p className="text-xs text-muted-foreground">Next-Gen Firewall</p>
              </div>
            )}
          </div>
          
          {/* Hamburger/Cross Button - Only for tablet */}
          {window.innerWidth >= 640 && window.innerWidth < 1024 && (
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-2 hover:bg-slate-800 rounded transition-colors"
              title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            >
              {isCollapsed ? (
                <Menu className="w-5 h-5 text-cyber-blue" />
              ) : (
                <X className="w-5 h-5 text-muted-foreground hover:text-cyber-blue" />
              )}
            </button>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className={cn(
        "flex-1 space-y-3",
        window.innerWidth < 640 ? "p-3" : (isCollapsed ? "p-2" : "p-4")
      )}>
        {navItems.map((item, idx) => (
          <NavLink
            key={idx}
            to={item.path}
            className={({ isActive }) =>
              cn(
                "flex items-center rounded-lg transition-all duration-200 group relative",
                window.innerWidth < 640 ? "justify-center p-3" : (isCollapsed ? "justify-center p-3" : "gap-3 px-4 py-3"),
                isActive
                  ? "bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/50"
                  : "text-muted-foreground hover:bg-slate-800 hover:text-white"
              )
            }
            title={item.name}
          >
            {({ isActive }) => (
              <>
                <item.icon className={cn(
                  "transition-transform group-hover:scale-110",
                  window.innerWidth < 640 ? "w-5 h-5" : "w-5 h-5",
                  isActive && "text-cyan-400"
                )} />
                {(window.innerWidth >= 1024 || (!isCollapsed && window.innerWidth >= 640)) && (
                  <>
                    <span className="font-medium">{item.name}</span>
                    {isActive && (
                      <motion.div
                        layoutId="activeIndicator"
                        className="ml-auto w-2 h-2 rounded-full bg-cyan-400"
                      />
                    )}
                  </>
                )}
                {(isCollapsed || window.innerWidth < 640) && isActive && (
                  <div className="absolute right-0 top-1/2 transform -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-l" />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Status Footer */}
      <div className={cn(
        "border-t border-slate-800",
        window.innerWidth < 640 ? "p-3" : (isCollapsed ? "p-2" : "p-4")
      )}>
        {(window.innerWidth < 1024 && (isCollapsed || window.innerWidth < 640)) ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-4 h-4 rounded-full bg-green-500 animate-pulse" title={`Status: ${stats.status}`}></div>
            {stats.ml_trained && (
              <Brain className="w-4 h-4 text-purple-400" title="AI Detection Active" />
            )}
          </div>
        ) : (
          <>
            <div className="bg-gradient-to-br from-green-900/20 to-green-800/20 border border-green-500/50 rounded-lg p-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span className="text-sm font-medium text-green-400 capitalize">{stats.status}</span>
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Live monitoring</span>
                <Activity className="w-3 h-3" />
              </div>
            </div>
            
            {stats.ml_trained && (
              <div className="mt-3 bg-gradient-to-br from-purple-900/20 to-purple-800/20 border border-purple-500/50 rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <Brain className="w-4 h-4 text-purple-400" />
                  <span className="text-xs font-medium text-purple-400">AI Detection Active</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </motion.div>
    </>
  )
}

export default Sidebar
