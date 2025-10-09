import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { BarChart3, TrendingUp, Activity, PieChart as PieChartIcon } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { 
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend 
} from 'recharts'

const Analytics = () => {
  const [stats, setStats] = useState({
    total_packets: 0,
    threats_detected: 0,
    ml_threats: 0,
    blocked_ips_count: 0
  })

  const [historicalData, setHistoricalData] = useState([])

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/stats')
        const data = await response.json()
        setStats(data)
        
        // Add to historical data
        setHistoricalData(prev => {
          const newData = [...prev, {
            time: new Date().toLocaleTimeString(),
            packets: data.total_packets,
            threats: data.threats_detected,
            mlThreats: data.ml_threats
          }]
          return newData.slice(-30)
        })
      } catch (error) {
        console.error('Error fetching stats:', error)
      }
    }

    fetchStats()
    const interval = setInterval(fetchStats, 2000)
    return () => clearInterval(interval)
  }, [])

  const threatDistribution = [
    { name: 'ML Detected', value: stats.ml_threats, color: '#8b5cf6' },
    { name: 'Rule-Based', value: Math.max(0, stats.threats_detected - stats.ml_threats), color: '#f97316' },
    { name: 'Safe', value: Math.max(0, stats.total_packets - stats.threats_detected), color: '#10b981' }
  ]

  const detectionRate = stats.total_packets > 0 ? ((stats.threats_detected / stats.total_packets) * 100).toFixed(1) : 0

  return (
    <div className="min-h-screen bg-cyber-dark p-3 sm:p-4 lg:p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-6 lg:mb-8 pt-16 lg:pt-0"
      >
        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-cyber-blue flex items-center gap-2 lg:gap-3">
          <BarChart3 className="w-6 h-6 sm:w-8 sm:h-8 lg:w-10 lg:h-10" />
          Analytics & Insights
        </h1>
        <p className="text-muted-foreground mt-1 text-sm lg:text-base">Detailed network security analytics and trends</p>
      </motion.div>

      {/* Real-time Metrics */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-4 lg:mb-6"
      >
        <Card className="bg-gradient-to-br from-cyan-900/20 to-cyan-800/20 border-cyan-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Packets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-cyan-400">{stats.total_packets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground mt-2">
              <TrendingUp className="w-3 h-3 inline mr-1" />
              Real-time
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-red-900/20 to-red-800/20 border-red-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Threats Detected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-400">{stats.threats_detected}</div>
            <p className="text-xs text-muted-foreground mt-2">
              <Activity className="w-3 h-3 inline mr-1" />
              Active monitoring
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-900/20 to-purple-800/20 border-purple-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">ML Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-purple-400">{stats.ml_threats}</div>
            <p className="text-xs text-muted-foreground mt-2">
              AI-powered detection
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-900/20 to-orange-800/20 border-orange-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Blocked IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-400">{stats.blocked_ips_count}</div>
            <p className="text-xs text-muted-foreground mt-2">
              Auto-blocked
            </p>
          </CardContent>
        </Card>
      </motion.div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6 mb-4 lg:mb-6">
        {/* Packet Flow Over Time */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-cyan-400">Packet Flow Over Time</CardTitle>
              <CardDescription>Real-time packet monitoring</CardDescription>
            </CardHeader>
            <CardContent className="focus:outline-none">
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={historicalData}>
                  <defs>
                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
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
                  <Area 
                    type="monotone" 
                    dataKey="packets" 
                    stroke="#00f0ff" 
                    fillOpacity={1} 
                    fill="url(#colorPackets)"
                    style={{ outline: 'none' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </motion.div>

        {/* Threat Detection Trends */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-red-400">Threat Detection Trends</CardTitle>
              <CardDescription>ML vs Rule-based detection</CardDescription>
            </CardHeader>
            <CardContent className="focus:outline-none">
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={historicalData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" style={{ outline: 'none' }} />
                  <YAxis stroke="#64748b" style={{ outline: 'none' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', outline: 'none' }}
                    labelStyle={{ color: '#94a3b8' }}
                    wrapperStyle={{ outline: 'none' }}
                  />
                  <Legend wrapperStyle={{ outline: 'none' }} />
                  <Line 
                    type="monotone" 
                    dataKey="threats" 
                    stroke="#ef4444" 
                    strokeWidth={2}
                    name="Total Threats"
                    style={{ outline: 'none' }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="mlThreats" 
                    stroke="#8b5cf6" 
                    strokeWidth={2}
                    name="ML Threats"
                    style={{ outline: 'none' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </motion.div>

        {/* Threat Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-purple-400 flex items-center gap-2">
                <PieChartIcon className="w-5 h-5" />
                Threat Distribution
              </CardTitle>
              <CardDescription>Detection method breakdown</CardDescription>
            </CardHeader>
            <CardContent className="focus:outline-none">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart style={{ cursor: 'default' }}>
                  <Pie
                    data={threatDistribution}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                    style={{ outline: 'none' }}
                  >
                    {threatDistribution.map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={entry.color} 
                        style={{ 
                          outline: 'none',
                          filter: 'none',
                          opacity: 1
                        }}
                      />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0f172a', 
                      border: '1px solid #475569', 
                      borderRadius: '8px',
                      color: '#94a3b8',
                      outline: 'none',
                      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
                    }}
                    labelStyle={{ color: '#94a3b8' }}
                    wrapperStyle={{ outline: 'none' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </motion.div>

        {/* Real-time Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-green-400">Real-time Statistics</CardTitle>
              <CardDescription>Current system metrics</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="p-4 bg-slate-800 rounded-lg">
                  <p className="text-sm text-muted-foreground mb-2">Detection Rate</p>
                  <p className="text-3xl font-bold text-green-400">{detectionRate}%</p>
                </div>
                <div className="p-4 bg-slate-800 rounded-lg">
                  <p className="text-sm text-muted-foreground mb-2">Total Packets Analyzed</p>
                  <p className="text-3xl font-bold text-cyan-400">{stats.total_packets.toLocaleString()}</p>
                </div>
                <div className="p-4 bg-slate-800 rounded-lg">
                  <p className="text-sm text-muted-foreground mb-2">Blocked IPs</p>
                  <p className="text-3xl font-bold text-orange-400">{stats.blocked_ips_count}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* System Summary */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
      >
        <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-cyber-blue">System Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div className="text-center p-4 bg-slate-800 rounded-lg">
                <p className="text-3xl font-bold text-cyan-400">{stats.total_packets.toLocaleString()}</p>
                <p className="text-sm text-muted-foreground mt-1">Total Packets</p>
              </div>
              <div className="text-center p-4 bg-slate-800 rounded-lg">
                <p className="text-3xl font-bold text-red-400">{stats.threats_detected}</p>
                <p className="text-sm text-muted-foreground mt-1">Threats Detected</p>
              </div>
              <div className="text-center p-4 bg-slate-800 rounded-lg">
                <p className="text-3xl font-bold text-purple-400">{stats.ml_threats}</p>
                <p className="text-sm text-muted-foreground mt-1">ML Threats</p>
              </div>
              <div className="text-center p-4 bg-slate-800 rounded-lg">
                <p className="text-3xl font-bold text-orange-400">{stats.blocked_ips_count}</p>
                <p className="text-sm text-muted-foreground mt-1">Blocked IPs</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

export default Analytics
