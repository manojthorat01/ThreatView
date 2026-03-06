import { useState, useEffect } from 'react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

const API = 'http://localhost:8000'
const COLORS = ['#6366f1', '#06b6d4', '#f59e0b', '#ef4444', '#10b981', '#8b5cf6']

const threatTag = (type) => {
  const map = { malware: ['#7f1d1d','#fca5a5'], phishing: ['#78350f','#fcd34d'], abuse: ['#1e3a5f','#93c5fd'], ransomware: ['#4c1d95','#c4b5fd'], botnet: ['#064e3b','#6ee7b7'] }
  const [bg, color] = map[type] || ['#1f2937','#9ca3af']
  return { display:'inline-block', padding:'2px 8px', borderRadius:'4px', fontSize:'11px', fontWeight:'600', background:bg, color }
}

const INDUSTRIES = ['Healthcare','Finance','Education','Government','Retail','Technology','Energy','Manufacturing','Legal','Other']

export default function App() {
  const [stats, setStats] = useState(null)
  const [indicators, setIndicators] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [alertEmail, setAlertEmail] = useState('')
  const [alertIndustry, setAlertIndustry] = useState('')
  const [alertDomain, setAlertDomain] = useState('')
  const [alertStatus, setAlertStatus] = useState(null)
  const [alertLoading, setAlertLoading] = useState(false)

  useEffect(() => {
    Promise.all([
      axios.get(`${API}/api/stats`),
      axios.get(`${API}/api/indicators?limit=25`)
    ]).then(([s, i]) => {
      setStats(s.data)
      setIndicators(i.data.items)
      setLoading(false)
    }).catch(err => {
      setError(err.message)
      setLoading(false)
    })
  }, [])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!searchQuery.trim()) return
    const res = await axios.get(`${API}/api/search?q=${encodeURIComponent(searchQuery)}`)
    setSearchResults(res.data)
  }

  const handleAlertRegister = async (e) => {
    e.preventDefault()
    if (!alertEmail.trim()) return
    setAlertLoading(true)
    try {
      const res = await axios.post(`${API}/api/alerts/register`, {
        email: alertEmail,
        industry: alertIndustry || null,
        domain: alertDomain || null
      })
      setAlertStatus({ success: true, message: res.data.message })
    } catch (err) {
      setAlertStatus({ success: false, message: 'Failed to register alert. Is the backend running?' })
    }
    setAlertLoading(false)
  }

  if (loading) return <div style={{minHeight:'100vh',background:'#0a0e1a',display:'flex',alignItems:'center',justifyContent:'center',color:'#6366f1',fontSize:'20px'}}>⚡ Loading ThreatView...</div>
  if (error) return <div style={{minHeight:'100vh',background:'#0a0e1a',display:'flex',alignItems:'center',justifyContent:'center',color:'#ef4444',fontSize:'16px'}}>❌ API Error: {error}</div>

  const otxCount = stats?.by_source?.find(x => x.source==='otx')?.count || 0
  const abuseCount = stats?.by_source?.find(x => x.source==='abuseipdb')?.count || 0

  const inputStyle = {width:'100%',background:'#1f2937',border:'1px solid #374151',borderRadius:'8px',padding:'10px 14px',color:'#e2e8f0',fontSize:'14px',outline:'none',marginBottom:'12px'}
  const btnStyle = {background:'#6366f1',color:'#fff',border:'none',borderRadius:'8px',padding:'10px 24px',cursor:'pointer',fontWeight:'600',fontSize:'14px'}
  const cardStyle = {background:'#111827',border:'1px solid #1f2937',borderRadius:'12px',padding:'24px'}
  const titleStyle = {fontSize:'16px',fontWeight:'600',marginBottom:'20px',color:'#f1f5f9'}

  return (
    <div style={{minHeight:'100vh',background:'#0a0e1a'}}>

      <div style={{background:'#111827',borderBottom:'1px solid #1f2937',padding:'16px 32px',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <div style={{fontSize:'22px',fontWeight:'700',color:'#6366f1'}}>🛡️ ThreatView</div>
        <div style={{display:'flex',alignItems:'center',gap:'16px'}}>
          <span style={{color:'#6b7280',fontSize:'13px'}}>Updated: {new Date().toLocaleTimeString()}</span>
          <span style={{background:'#10b981',color:'#fff',fontSize:'11px',padding:'3px 10px',borderRadius:'20px',fontWeight:'600'}}>● LIVE</span>
          <a href="http://localhost:8000/api/report/pdf" target="_blank" style={{background:'#1f2937',color:'#e2e8f0',border:'1px solid #374151',borderRadius:'8px',padding:'8px 16px',cursor:'pointer',fontWeight:'600',fontSize:'13px',textDecoration:'none'}}>📄 Download Report</a>        </div>
      </div>

      <div style={{padding:'32px',maxWidth:'1400px',margin:'0 auto'}}>

        {/* Stat Cards */}
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:'20px',marginBottom:'28px'}}>
          {[
            {num: stats?.total_indicators?.toLocaleString(), label:'Total Threat Indicators', color:'#6366f1'},
            {num: abuseCount, label:'Malicious IPs (AbuseIPDB)', color:'#ef4444'},
            {num: otxCount, label:'OTX Threat Indicators', color:'#f59e0b'},
          ].map((c,i) => (
            <div key={i} style={cardStyle}>
              <div style={{fontSize:'36px',fontWeight:'800',color:c.color}}>{c.num}</div>
              <div style={{color:'#9ca3af',fontSize:'14px',marginTop:'4px'}}>{c.label}</div>
            </div>
          ))}
        </div>

        {/* Charts */}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px',marginBottom:'28px'}}>
          <div style={cardStyle}>
            <div style={titleStyle}>Threats by Type</div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={stats?.by_threat_type}>
                <XAxis dataKey="type" stroke="#6b7280" tick={{fontSize:11}} />
                <YAxis stroke="#6b7280" tick={{fontSize:11}} />
                <Tooltip contentStyle={{background:'#1f2937',border:'1px solid #374151',borderRadius:'8px',color:'#e2e8f0'}} />
                <Bar dataKey="count" fill="#6366f1" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={cardStyle}>
            <div style={titleStyle}>Top Attack Origins</div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={stats?.top_countries?.slice(0,6)} dataKey="count" nameKey="country" cx="50%" cy="50%" outerRadius={75} label={({country,percent})=>`${country} ${(percent*100).toFixed(0)}%`} labelLine={false}>
                  {stats?.top_countries?.slice(0,6).map((_,i)=><Cell key={i} fill={COLORS[i%COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{background:'#1f2937',border:'1px solid #374151',borderRadius:'8px',color:'#e2e8f0'}} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Search + Alerts side by side */}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px',marginBottom:'28px'}}>

          {/* IoC Search */}
          <div style={cardStyle}>
            <div style={titleStyle}>🔍 IoC Search</div>
            <form onSubmit={handleSearch}>
              <input style={inputStyle} placeholder="Paste a suspicious IP, domain, or hash..." value={searchQuery} onChange={e=>setSearchQuery(e.target.value)} />
              <button type="submit" style={btnStyle}>Search Threat Database</button>
            </form>
            {searchResults && (
              <div style={{marginTop:'16px'}}>
                <div style={{color:searchResults.found>0?'#ef4444':'#10b981',fontWeight:'600',marginBottom:'10px'}}>
                  {searchResults.found>0 ? `⚠️ THREAT DETECTED — ${searchResults.found} match(es)` : `✅ Clean — not found in threat database`}
                </div>
                {searchResults.results.map((r,i)=>(
                  <div key={i} style={{background:'#1f2937',borderRadius:'8px',padding:'12px',marginBottom:'8px',border:'1px solid #374151'}}>
                    <div style={{fontFamily:'monospace',color:'#a5b4fc',fontWeight:'600',marginBottom:'4px'}}>{r.value}</div>
                    <div style={{color:'#9ca3af',fontSize:'12px',display:'flex',gap:'12px',flexWrap:'wrap'}}>
                      <span>Type: <span style={{color:'#e2e8f0'}}>{r.type}</span></span>
                      <span>Threat: <span style={threatTag(r.threat_type)}>{r.threat_type}</span></span>
                      <span>Country: <span style={{color:'#e2e8f0'}}>{r.country||'Unknown'}</span></span>
                      <span>Confidence: <span style={{color:'#f59e0b'}}>{r.confidence}%</span></span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Alert Registration */}
          <div style={cardStyle}>
            <div style={titleStyle}>🔔 Custom Threat Alerts</div>
            <p style={{color:'#9ca3af',fontSize:'13px',marginBottom:'16px'}}>
              Get emailed when threats matching your industry or domain are detected.
            </p>
            <form onSubmit={handleAlertRegister}>
              <input style={inputStyle} type="email" placeholder="Your email address *" value={alertEmail} onChange={e=>setAlertEmail(e.target.value)} required />
              <select style={{...inputStyle,cursor:'pointer'}} value={alertIndustry} onChange={e=>setAlertIndustry(e.target.value)}>
                <option value="">Select your industry (optional)</option>
                {INDUSTRIES.map(ind => <option key={ind} value={ind}>{ind}</option>)}
              </select>
              <input style={inputStyle} placeholder="Your domain to monitor e.g. mycompany.com (optional)" value={alertDomain} onChange={e=>setAlertDomain(e.target.value)} />
              <button type="submit" style={{...btnStyle, opacity: alertLoading ? 0.7 : 1}} disabled={alertLoading}>
                {alertLoading ? 'Registering...' : 'Register for Alerts'}
              </button>
            </form>
            {alertStatus && (
              <div style={{marginTop:'12px',padding:'12px',borderRadius:'8px',background: alertStatus.success ? '#064e3b' : '#7f1d1d',color: alertStatus.success ? '#6ee7b7' : '#fca5a5',fontSize:'13px',fontWeight:'600'}}>
                {alertStatus.success ? '✅' : '❌'} {alertStatus.message}
              </div>
            )}
          </div>
        </div>

        {/* IoC Table */}
        <div style={cardStyle}>
          <div style={titleStyle}>🚨 Recent Indicators of Compromise (IoCs)</div>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:'13px'}}>
            <thead>
              <tr>
                {['Indicator Value','Type','Threat','Source','Country','Confidence'].map(h=>(
                  <th key={h} style={{textAlign:'left',padding:'10px 12px',color:'#6b7280',borderBottom:'1px solid #1f2937',fontSize:'11px',textTransform:'uppercase',letterSpacing:'0.05em'}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {indicators.map(ind=>(
                <tr key={ind.id}>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937',fontFamily:'monospace',color:'#a5b4fc',maxWidth:'260px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{ind.value}</td>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937',color:'#d1d5db'}}>{ind.type}</td>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937'}}><span style={threatTag(ind.threat_type)}>{ind.threat_type}</span></td>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937',color:'#d1d5db'}}>{ind.source}</td>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937',color:'#d1d5db'}}>{ind.country||'—'}</td>
                  <td style={{padding:'10px 12px',borderBottom:'1px solid #1f2937'}}>
                    <div style={{display:'flex',alignItems:'center',gap:'8px'}}>
                      <div style={{background:'#1f2937',borderRadius:'4px',height:'6px',width:'60px'}}>
                        <div style={{background:ind.confidence>75?'#ef4444':ind.confidence>40?'#f59e0b':'#6366f1',height:'100%',width:`${Math.min(ind.confidence,100)}%`,borderRadius:'4px'}} />
                      </div>
                      <span style={{fontSize:'12px',color:'#d1d5db'}}>{ind.confidence}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  )
}
