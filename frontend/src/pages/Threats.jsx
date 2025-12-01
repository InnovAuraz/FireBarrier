import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { AlertTriangle, Shield, Ban, CheckCircle, Brain, Filter, Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'

const Threats = () => {
  const [threats, setThreats] = useState([])
  const [stats, setStats] = useState({
    threats_detected: 0,
    ml_threats: 0,
    ml_trained: false
  })
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [threatsRes, statsRes] = await Promise.all([
          fetch('http://localhost:8000/api/threats'),
          fetch('http://localhost:8000/api/stats')
        ])
        const threatsData = await threatsRes.json()
        const statsData = await statsRes.json()
        console.log('Threats data:', threatsData)
        console.log('Sample threat:', threatsData[0])
        setThreats(threatsData)
        setStats(statsData)
      } catch (error) {
        console.error('Error fetching data:', error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  const filteredThreats = threats.filter(threat => {
    const matchesFilter = filter === 'all' || 
      (filter === 'ml' && threat.detection_method === 'ML') ||
      (filter === 'rule' && threat.detection_method?.toLowerCase().includes('rule')) ||
      (filter === 'blocked' && threat.blocked)
    
    const matchesSearch = !searchTerm || 
      threat.src_ip?.includes(searchTerm) ||
      threat.dst_ip?.includes(searchTerm) ||
      threat.type?.toLowerCase().includes(searchTerm.toLowerCase())
    
    return matchesFilter && matchesSearch
  })

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
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-red-500 flex items-center gap-2 lg:gap-3">
              <AlertTriangle className="w-6 h-6 sm:w-8 sm:h-8 lg:w-10 lg:h-10" />
              Threat Detection
            </h1>
            <p className="text-muted-foreground mt-1 text-sm lg:text-base">Real-time threat monitoring and analysis</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:gap-4">
            <Badge variant="destructive" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm animate-pulse">
              {stats.threats_detected} Active Threats
            </Badge>
            {stats.ml_trained && (
              <Badge variant="secondary" className="px-3 py-1 lg:px-4 lg:py-2 text-xs lg:text-sm bg-purple-900 text-purple-300">
                <Brain className="w-3 h-3 lg:w-4 lg:h-4 mr-1 lg:mr-2" />
                {stats.ml_threats} ML Detected
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
        <Card className="bg-gradient-to-br from-red-900/20 to-red-800/20 border-red-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{threats.length}</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-900/20 to-purple-800/20 border-purple-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">ML Detected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-purple-500">
              {threats.filter(t => t.detection_method === 'ML').length}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-900/20 to-orange-800/20 border-orange-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Rule-Based</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-500">
              {threats.filter(t => t.detection_method?.toLowerCase().includes('rule')).length}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-900/20 to-green-800/20 border-green-500/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">Blocked</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-500">
              {threats.filter(t => t.blocked).length}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Filters and Search */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="mb-6"
      >
        <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
          <CardContent className="p-4">
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Filter className="w-5 h-5 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">Filter:</span>
              </div>
              <div className="flex gap-2">
                <Button
                  variant={filter === 'all' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('all')}
                >
                  All
                </Button>
                <Button
                  variant={filter === 'ml' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('ml')}
                  className="bg-purple-900 hover:bg-purple-800"
                >
                  <Brain className="w-4 h-4 mr-2" />
                  ML
                </Button>
                <Button
                  variant={filter === 'rule' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('rule')}
                >
                  Rule-Based
                </Button>
                <Button
                  variant={filter === 'blocked' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter('blocked')}
                >
                  <Ban className="w-4 h-4 mr-2" />
                  Blocked
                </Button>
              </div>
              <div className="flex-1 max-w-md ml-auto">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search by IP or type..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-cyber-blue"
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Threats Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-gradient-to-br from-slate-900 to-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-red-400 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Detected Threats
            </CardTitle>
          </CardHeader>
          <CardContent>
            {filteredThreats.length > 0 ? (
              <div className="overflow-x-auto -mx-4 sm:mx-0">
                <table className="w-full min-w-[700px]">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Source IP</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Destination IP</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Port</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Type</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Detection</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">MITRE ATT&CK</th>
                      <th className="text-left p-4 text-sm font-medium text-muted-foreground">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredThreats.slice(0, 20).map((threat, idx) => (
                      <motion.tr
                        key={idx}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                        className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors"
                      >
                        <td className="p-4">
                          <span className="text-cyber-blue font-mono text-sm">
                            {threat.src_ip || 'N/A'}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className="text-cyan-400 font-mono text-sm">
                            {threat.dst_ip || 'N/A'}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className="text-red-400 font-mono text-sm">
                            {threat.dst_port || threat.src_port || 'N/A'}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className="text-sm">{threat.type || 'OTHER'}</span>
                        </td>
                        <td className="p-4">
                          {threat.detection_method === 'ML' ? (
                            <Badge variant="secondary" className="bg-purple-900 text-purple-300">
                              <Brain className="w-3 h-3 mr-1" />
                              ML
                            </Badge>
                          ) : (
                            <Badge variant="warning" className="bg-orange-900 text-orange-300">
                              Rule
                            </Badge>
                          )}
                        </td>
                        <td className="p-4">
                          <div className="flex flex-wrap gap-1">
                            {threat.mitre_tactics && threat.mitre_tactics.length > 0 ? (
                              threat.mitre_tactics.map((tactic, i) => (
                                <Badge 
                                  key={i} 
                                  variant="outline" 
                                  className="text-xs border-cyan-500 text-cyan-400"
                                  title={`${tactic.tactic}: ${tactic.name}`}
                                >
                                  {tactic.technique}
                                </Badge>
                              ))
                            ) : (
                              <span className="text-xs text-muted-foreground">-</span>
                            )}
                          </div>
                        </td>
                        <td className="p-4">
                          {threat.blocked ? (
                            <Badge variant="destructive" className="flex items-center gap-1 w-fit">
                              <Ban className="w-3 h-3" />
                              Blocked
                            </Badge>
                          ) : (
                            <Badge variant="warning" className="flex items-center gap-1 w-fit">
                              <AlertTriangle className="w-3 h-3" />
                              Flagged
                            </Badge>
                          )}
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-12">
                <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                <p className="text-xl font-bold text-green-500">No Threats Detected</p>
                <p className="text-muted-foreground mt-2">Your network is secure</p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

export default Threats
