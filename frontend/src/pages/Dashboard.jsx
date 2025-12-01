import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, Activity, AlertTriangle, Brain, Ban, Zap } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

const Dashboard = () => {
  const [stats, setStats] = useState({
    total_packets: 0,
    threats_detected: 0,
    ml_threats: 0,
    lstm_threats: 0,
    cnn_threats: 0,  // NEW: Layer 5
    ml_trained: false,
    lstm_trained: false,
    cnn_trained: false,  // NEW
    blocked_ips_count: 0,
    status: 'connecting...'
  })

  const [threats, setThreats] = useState([])
  const [blockedIPs, setBlockedIPs] = useState([])
  const [networkData, setNetworkData] = useState([])

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, threatsRes, blockedIPsRes] = await Promise.all([
          fetch('http://localhost:8000/api/stats'),
          fetch('http://localhost:8000/api/threats'),
          fetch('http://localhost:8000/api/blocked-ips')
        ])
        
        const statsData = await statsRes.json()
        const threatsData = await threatsRes.json()
        const blockedIPsData = await blockedIPsRes.json()
        
        setStats(statsData)
        setThreats(threatsData)
        setBlockedIPs(blockedIPsData.blocked_ips || [])
        
        // Update network data for real-time chart
        setNetworkData(prev => {
          const newData = [...prev, {
            time: new Date().toLocaleTimeString(),
            packets: statsData.total_packets,
            threats: statsData.threats_detected
          }]
          return newData.slice(-20)
        })
      } catch (error) {
        console.error('Backend not connected:', error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  const handleUnblock = async (ip) => {
    try {
      const response = await fetch(`http://localhost:8000/api/unblock-ip/${ip}`, {
        method: 'POST'
      })
      const data = await response.json()
      if (data.success) {
        alert(`✅ ${ip} has been unblocked!`)
      }
    } catch (error) {
      console.error('Unblock failed:', error)
    }
  }

  const threatLevel = stats.threats_detected > 10 ? 'HIGH' : stats.threats_detected > 5 ? 'MEDIUM' : 'LOW'
  const threatLevelColor = threatLevel === 'HIGH' ? 'text-red-500' : threatLevel === 'MEDIUM' ? 'text-yellow-500' : 'text-green-500'

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
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-cyber-blue flex items-center gap-2 lg:gap-3">
              <Shield className="w-6 h-6 sm:w-8 sm:h-8 lg:w-10 lg:h-10" />
              AI-NGFW Dashboard
            </h1>
            <p className="text-muted-foreground mt-1 text-sm lg:text-base">Real-time Network Security Monitoring</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:gap-4">
            <Badge variant="success" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm">
              {stats.status}
            </Badge>
            {stats.ml_trained && (
              <Badge variant="secondary" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm bg-purple-900 text-purple-300">
                <Brain className="w-3 h-3 lg:w-4 lg:h-4 mr-1 lg:mr-2" />
                ML Active
              </Badge>
            )}
            {/* NEW: LSTM Badge */}
            {stats.lstm_trained && (
              <Badge variant="secondary" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm bg-blue-900 text-blue-300">
                <Zap className="w-3 h-3 lg:w-4 lg:h-4 mr-1 lg:mr-2" />
                LSTM Active
              </Badge>
            )}
            {/* NEW: CNN Badge */}
            {stats.cnn_trained && (
              <Badge variant="secondary" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm bg-purple-900 text-purple-300">
                <Brain className="w-3 h-3 lg:w-4 lg:h-4 mr-1 lg:mr-2" />
                CNN Active
              </Badge>
            )}
          </div>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-4 lg:mb-6"
      >
        {/* Total Packets */}
        <Card className="bg-gradient-to-br from-cyan-900/20 to-cyan-800/20 border-cyan-500/50 hover:border-cyan-500 transition-all">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Packets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-cyan-400">{stats.total_packets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground mt-2">
              <Activity className="w-3 h-3 inline mr-1" />
              Live monitoring
            </p>
          </CardContent>
        </Card>

        {/* Threats Detected */}
        <Card className={`bg-gradient-to-br from-red-900/20 to-red-800/20 border-red-500/50 hover:border-red-500 transition-all ${
          stats.threats_detected > 0 ? 'animate-pulse' : ''
        }`}>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Threats Detected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-red-400">{stats.threats_detected}</div>
            {stats.threats_detected > 0 && (
              <p className="text-xs text-red-400 mt-2 animate-pulse">
                <AlertTriangle className="w-3 h-3 inline mr-1" />
                Active threats!
              </p>
            )}
          </CardContent>
        </Card>

        {/* ML Threats */}
        {stats.ml_trained && (
          <Card className="bg-gradient-to-br from-purple-900/20 to-purple-800/20 border-purple-500/50 hover:border-purple-500 transition-all">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">ML Threats</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-purple-400">{stats.ml_threats}</div>
              <p className="text-xs text-muted-foreground mt-2">
                <Brain className="w-3 h-3 inline mr-1" />
                AI Detection
              </p>
            </CardContent>
          </Card>
        )}

        {/* NEW: LSTM Threats */}
        {stats.lstm_trained && (
          <Card className="bg-gradient-to-br from-blue-900/20 to-blue-800/20 border-blue-500/50 hover:border-blue-500 transition-all">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">LSTM Threats</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-blue-400">{stats.lstm_threats}</div>
              <p className="text-xs text-muted-foreground mt-2">
                <Zap className="w-3 h-3 inline mr-1" />
                Sequential
              </p>
            </CardContent>
          </Card>
        )}

        {/* NEW: CNN Threats */}
        {stats.cnn_trained && (
          <Card className="bg-gradient-to-br from-purple-900/20 to-purple-800/20 border-purple-500/50 hover:border-purple-500 transition-all">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">CNN Threats</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-purple-400">{stats.cnn_threats}</div>
              <p className="text-xs text-muted-foreground mt-2">
                <Brain className="w-3 h-3 inline mr-1" />
                Pattern Detection
              </p>
            </CardContent>
          </Card>
        )}

        {/* Blocked IPs */}
        <Card className="bg-gradient-to-br from-orange-900/20 to-orange-800/20 border-orange-500/50 hover:border-orange-500 transition-all">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Blocked IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl sm:text-3xl lg:text-4xl font-bold text-orange-400">{stats.blocked_ips_count}</div>
            <p className="text-xs text-muted-foreground mt-2">
              <Ban className="w-3 h-3 inline mr-1" />
              Auto-blocked
            </p>
          </CardContent>
        </Card>
      </motion.div>

      {/* Threat Level Indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="mb-6"
      >
        <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Current Threat Level</p>
                <div className={`text-3xl sm:text-4xl lg:text-5xl font-bold ${threatLevelColor}`}>{threatLevel}</div>
              </div>
              <AlertTriangle className={`w-20 h-20 ${threatLevelColor.replace('text-', 'text-')}/20`} />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Network Activity Chart */}
      {networkData.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="mb-6"
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-cyber-blue">Network Activity</CardTitle>
            </CardHeader>
            <CardContent className="focus:outline-none">
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={networkData}>
                  <defs>
                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" style={{ outline: 'none' }} />
                  <YAxis stroke="#64748b" style={{ outline: 'none' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', outline: 'none' }}
                    labelStyle={{ color: '#94a3b8' }}
                    wrapperStyle={{ outline: 'none' }}
                  />
                  <Area type="monotone" dataKey="packets" stroke="#00f0ff" fillOpacity={1} fill="url(#colorPackets)" name="Packets" style={{ outline: 'none' }} />
                  <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" name="Threats" style={{ outline: 'none' }} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Security Alert */}
      {stats.threats_detected > 0 && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.4 }}
          className="mb-6"
        >
          <Card className="bg-gradient-to-br from-red-900/20 to-red-800/20 border-red-500 animate-pulse">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <AlertTriangle className="w-12 h-12 text-red-500" />
                <div>
                  <h3 className="text-xl font-bold text-red-400">Security Alert</h3>
                  <p className="text-red-300">{stats.threats_detected} suspicious packet(s) detected and blocked</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Blocked IPs Section */}
      {blockedIPs.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mb-6"
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-orange-500/50">
            <CardHeader>
              <CardTitle className="text-orange-400 flex items-center gap-2">
                <Ban className="w-5 h-5" />
                Blocked IP Addresses
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-4">
                {blockedIPs.map((ip, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 bg-slate-800 rounded-lg border border-orange-600/50 hover:border-orange-500 transition-colors">
                    <div className="flex items-center gap-3">
                      <Ban className="w-6 h-6 text-orange-500" />
                      <div>
                        <p className="font-mono text-lg font-bold text-orange-400">{ip}</p>
                        <p className="text-xs text-muted-foreground">Auto-blocked by firewall</p>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleUnblock(ip)}
                      className="hover:bg-green-500/20 hover:border-green-500 hover:text-green-500"
                    >
                      Unblock
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Recent Threats Table */}
      {threats.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-red-500/50">
            <CardHeader>
              <CardTitle className="text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Recent Threats
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto -mx-4 sm:mx-0">
                <table className="w-full min-w-[600px]">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Source IP</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Destination IP</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Port</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Type</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Size</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Detection</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.slice(0, 10).map((threat, idx) => (
                      <tr key={idx} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                        <td className="p-4 text-cyan-400 font-mono text-sm">{threat.src_ip || 'N/A'}</td>
                        <td className="p-4 text-cyan-400 font-mono text-sm">{threat.dst_ip || 'N/A'}</td>
                        <td className="p-4 text-red-400 font-mono text-sm">{threat.dst_port || threat.src_port || 'N/A'}</td>
                        <td className="p-4 text-sm">{threat.type || 'OTHER'}</td>
                        <td className="p-4 text-sm text-muted-foreground">{threat.size} bytes</td>
                        <td className="p-4">
                          {threat.detection_method === 'ML' ? (
                            <Badge variant="secondary" className="bg-purple-900 text-purple-300">
                              <Brain className="w-3 h-3 mr-1" />
                              ML
                            </Badge>
                          ) : threat.detection_method?.includes('LSTM') ? (
                            <Badge variant="secondary" className="bg-blue-900 text-blue-300">
                              <Zap className="w-3 h-3 mr-1" />
                              LSTM
                            </Badge>
                          ) : threat.detection_method?.includes('CNN') ? (
                            <Badge variant="secondary" className="bg-purple-900 text-purple-300">
                              <Brain className="w-3 h-3 mr-1" />
                              CNN
                            </Badge>
                          ) : (
                            <Badge variant="warning" className="bg-orange-900 text-orange-300">
                              Rule
                            </Badge>
                          )}
                        </td>
                        <td className="p-4">
                          {threat.blocked ? (
                            <Badge variant="destructive">
                              <Ban className="w-3 h-3 mr-1" />
                              BLOCKED
                            </Badge>
                          ) : (
                            <Badge variant="warning">
                              <AlertTriangle className="w-3 h-3 mr-1" />
                              FLAGGED
                            </Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* ML & LSTM & CNN Detection Badges */}
      {(stats.ml_trained || stats.lstm_trained || stats.cnn_trained) && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="fixed bottom-6 right-6 space-y-4"
        >
          {stats.ml_trained && (
            <Card className="bg-gradient-to-br from-purple-900 to-purple-800 border-purple-500 shadow-lg shadow-purple-500/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Brain className="w-6 h-6 text-purple-300 animate-pulse" />
                  <div>
                    <p className="text-sm font-bold text-white">AI Detection Active</p>
                    <p className="text-xs text-purple-300">{stats.ml_threats} ML Threats Detected</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          
          {stats.lstm_trained && (
            <Card className="bg-gradient-to-br from-blue-900 to-blue-800 border-blue-500 shadow-lg shadow-blue-500/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Zap className="w-6 h-6 text-blue-300 animate-pulse" />
                  <div>
                    <p className="text-sm font-bold text-white">LSTM Detection Active</p>
                    <p className="text-xs text-blue-300">{stats.lstm_threats} Sequential Threats</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          
          {stats.cnn_trained && (
            <Card className="bg-gradient-to-br from-violet-900 to-violet-800 border-violet-500 shadow-lg shadow-violet-500/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Brain className="w-6 h-6 text-violet-300 animate-pulse" />
                  <div>
                    <p className="text-sm font-bold text-white">CNN Detection Active</p>
                    <p className="text-xs text-violet-300">{stats.cnn_threats} Pattern Threats</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </motion.div>
      )}
    </div>
  )
}

export default Dashboard
