import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Ban, Shield, Unlock, Search, AlertCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'

const BlockedIPs = () => {
  const [blockedIPs, setBlockedIPs] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [unblocking, setUnblocking] = useState(null)

  useEffect(() => {
    const fetchBlockedIPs = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/blocked-ips')
        const data = await response.json()
        setBlockedIPs(data.blocked_ips || [])
      } catch (error) {
        console.error('Error fetching blocked IPs:', error)
      }
    }

    fetchBlockedIPs()
    const interval = setInterval(fetchBlockedIPs, 2000)
    return () => clearInterval(interval)
  }, [])

  const handleUnblock = async (ip) => {
    setUnblocking(ip)
    try {
      const response = await fetch(`http://localhost:8000/api/unblock-ip/${ip}`, {
        method: 'POST'
      })
      const data = await response.json()
      if (data.success) {
        setBlockedIPs(prev => prev.filter(blockedIp => blockedIp !== ip))
      }
    } catch (error) {
      console.error('Unblock failed:', error)
    } finally {
      setUnblocking(null)
    }
  }

  const filteredIPs = blockedIPs.filter(ip => 
    ip.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="min-h-screen bg-cyber-dark p-3 sm:p-4 lg:p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-6 lg:mb-8 pt-16 lg:pt-0"
      >
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-orange-500 flex items-center gap-2 lg:gap-3">
              <Ban className="w-6 h-6 sm:w-8 sm:h-8 lg:w-10 lg:h-10" />
              Blocked IP Addresses
            </h1>
            <p className="text-muted-foreground mt-1 text-sm lg:text-base">Manage blocked IP addresses and firewall rules</p>
          </div>
          <Badge variant="warning" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm">
            {blockedIPs.length} IPs Blocked
          </Badge>
        </div>
      </motion.div>

      {/* Stats Card */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="mb-6"
      >
        <Card className="bg-gradient-to-br from-orange-900/20 to-orange-800/20 border-orange-500/50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Total Blocked IPs</p>
                <p className="text-5xl font-bold text-orange-500">{blockedIPs.length}</p>
              </div>
              <Shield className="w-20 h-20 text-orange-500/20" />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Search */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="mb-6"
      >
        <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
          <CardContent className="p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search blocked IP addresses..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-12 pr-4 py-3 bg-slate-800 border border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500"
              />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Blocked IPs Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        {filteredIPs.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredIPs.map((ip, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: idx * 0.05 }}
              >
                <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-orange-500/50 hover:border-orange-500 transition-all duration-300 group">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 rounded-full bg-orange-500/20 flex items-center justify-center group-hover:bg-orange-500/30 transition-colors">
                          <Ban className="w-6 h-6 text-orange-500" />
                        </div>
                        <div>
                          <p className="font-mono text-lg font-bold text-orange-400">{ip}</p>
                          <p className="text-xs text-muted-foreground">Auto-blocked by firewall</p>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center justify-between pt-4 border-t border-slate-700">
                      <Badge variant="destructive" className="text-xs">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        Blocked
                      </Badge>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleUnblock(ip)}
                        disabled={unblocking === ip}
                        className="hover:bg-green-500/20 hover:border-green-500 hover:text-green-500"
                      >
                        {unblocking === ip ? (
                          <>
                            <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-2" />
                            Unblocking...
                          </>
                        ) : (
                          <>
                            <Unlock className="w-4 h-4 mr-2" />
                            Unblock
                          </>
                        )}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        ) : (
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardContent className="p-12">
              <div className="text-center">
                <Shield className="w-20 h-20 text-green-500 mx-auto mb-4" />
                <h3 className="text-2xl font-bold text-green-500 mb-2">No Blocked IPs</h3>
                <p className="text-muted-foreground">
                  {searchTerm ? 'No IPs match your search' : 'All IP addresses are currently allowed'}
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </motion.div>

      {/* Info Card */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="mt-6"
      >
        <Card className="bg-gradient-to-br from-blue-900/20 to-blue-800/20 border-blue-500/50">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-blue-400 mb-1">About IP Blocking</p>
                <p className="text-xs text-muted-foreground">
                  IP addresses are automatically blocked when malicious activity is detected. 
                  You can manually unblock IPs if they were blocked by mistake. 
                  Blocked IPs are prevented from accessing your network resources.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

export default BlockedIPs
