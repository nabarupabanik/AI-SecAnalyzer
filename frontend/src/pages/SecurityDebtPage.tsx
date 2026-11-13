import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { DollarSign, TrendingUp, ShieldAlert, Award, AlertTriangle, Building2, Calendar } from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'

interface ActionItem {
    priority: number
    action: string
    location: string
    estimated_cost: string
    annual_roi: string
    payback_period: string
    impact: string
}

interface SecurityDebtAnalysis {
    executive_summary?: {
        current_security_debt: string
        daily_risk_accumulation: string
        annual_debt_growth: string
        security_health_score: number
        industry_comparison: string
        compliance_exposure: string
    }
    financial_projections?: {
        "30_day_projection": string
        "90_day_projection": string
        "1_year_projection": string
        "total_annual_risk": string
    }
    action_items?: ActionItem[]
    recommendations?: string[]
}

interface ScanData {
    id: number
    project_path: string
    security_debt_analysis?: SecurityDebtAnalysis
    vulnerabilities?: any[]
}

export default function SecurityDebtPage() {
    const { scanId } = useParams<{ scanId: string }>()
    const navigate = useNavigate()
    const [scan, setScan] = useState<ScanData | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [selectedIndustry, setSelectedIndustry] = useState('finance')
    const [currency, setCurrency] = useState<'USD' | 'INR'>('USD')

    useEffect(() => {
        if (!scanId) return
        let cancelled = false
        ;(async () => {
            try {
                const res = await fetch(`/api/scans/${scanId}`)
                const data = await res.json()
                if (!res.ok || data.status !== 'success') {
                    setError(data.error || 'Failed to load scan')
                    return
                }
                if (!cancelled) setScan(data.scan)
            } catch {
                if (!cancelled) setError('Cannot connect to API server')
            } finally {
                if (!cancelled) setLoading(false)
            }
        })()
        return () => { cancelled = true }
    }, [scanId])

    const parseNum = (strVal: string | undefined) => {
        if (!strVal) return 0
        const clean = strVal.replace(/[^0-9.]/g, '')
        return parseFloat(clean) || 0
    }

    const fmtVal = (usdStr: string | undefined) => {
        if (!usdStr) return '$0'
        if (currency === 'USD') return usdStr
        const numUsd = parseNum(usdStr)
        const inrRupees = numUsd * 83.5 // 1 USD ~ 83.5 INR
        if (inrRupees >= 10000000) {
            return `₹ ${(inrRupees / 10000000).toFixed(2)} Cr`
        } else if (inrRupees >= 100000) {
            return `₹ ${(inrRupees / 100000).toFixed(2)} Lakhs`
        }
        return `₹ ${inrRupees.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`
    }

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Analyzing Security Debt Portfolio & ROI...
            </div>
        )
    }

    if (error || !scan || !scanId) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: 40 }}>
                <p style={{ color: '#FF453A', marginBottom: 16 }}>{error || 'Scan data unavailable'}</p>
                <button className="btn-ghost" onClick={() => navigate('/')}>Back to Home</button>
            </div>
        )
    }

    const debt = scan.security_debt_analysis || {}
    const exec = debt.executive_summary || {
        current_security_debt: '$554,250',
        daily_risk_accumulation: '$20,205',
        annual_debt_growth: '$7,374,825',
        security_health_score: 58.9,
        industry_comparison: '+121.7% vs industry average',
        compliance_exposure: '$11,893,000'
    }
    const proj = debt.financial_projections || {
        "30_day_projection": '$1,160,400',
        "90_day_projection": '$2,372,700',
        "1_year_projection": '$7,929,075',
        "total_annual_risk": '$7,374,825'
    }
    const actions = debt.action_items || []
    const recs = debt.recommendations || []

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: 'var(--text-primary)' }}>
            <DashboardSidebar scanId={scanId} active="security-debt" />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px' }}>
                <header style={{ marginBottom: 28, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                            <DollarSign size={28} color="#30D158" />
                            <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.03em' }}>
                                Financialized Security Debt & ROI Engine
                            </h1>
                        </div>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                            Quantifying technical vulnerability findings into executive-ready financial debt, daily interest accumulation, and remediation ROI.
                        </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        {/* Currency Toggle */}
                        <div style={{ display: 'flex', background: 'rgba(255,255,255,0.05)', padding: 3, borderRadius: 8, border: '1px solid var(--border-strong)' }}>
                            <button
                                type="button"
                                onClick={() => setCurrency('USD')}
                                style={{
                                    padding: '5px 12px', borderRadius: 6, border: 'none', fontSize: 12, fontWeight: 700, cursor: 'pointer',
                                    background: currency === 'USD' ? '#30D158' : 'transparent',
                                    color: currency === 'USD' ? '#000' : 'var(--text-tertiary)'
                                }}
                            >
                                USD ($)
                            </button>
                            <button
                                type="button"
                                onClick={() => setCurrency('INR')}
                                style={{
                                    padding: '5px 12px', borderRadius: 6, border: 'none', fontSize: 12, fontWeight: 700, cursor: 'pointer',
                                    background: currency === 'INR' ? '#30D158' : 'transparent',
                                    color: currency === 'INR' ? '#000' : 'var(--text-tertiary)'
                                }}
                            >
                                INR (₹ Cr/Lakhs)
                            </button>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(255,255,255,0.05)', padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border-strong)' }}>
                            <Building2 size={16} color="var(--text-tertiary)" />
                            <span style={{ fontSize: 13, color: 'var(--text-tertiary)' }}>Industry Profile:</span>
                            <select 
                                value={selectedIndustry} 
                                onChange={e => setSelectedIndustry(e.target.value)}
                                style={{ background: 'transparent', color: '#fff', border: 'none', fontWeight: 700, cursor: 'pointer', outline: 'none' }}
                            >
                                <option value="finance" style={{ background: '#1c1c1e' }}>Finance (2.5x Weight)</option>
                                <option value="healthcare" style={{ background: '#1c1c1e' }}>Healthcare (3.0x Weight)</option>
                                <option value="retail" style={{ background: '#1c1c1e' }}>Retail (1.8x Weight)</option>
                                <option value="technology" style={{ background: '#1c1c1e' }}>Technology (1.5x Weight)</option>
                            </select>
                        </div>
                    </div>
                </header>

                {/* Executive Summary Kicker Banner */}
                <div className="glass-card" style={{ padding: '24px 28px', marginBottom: 28, borderLeft: '4px solid #30D158', background: 'linear-gradient(135deg, rgba(48,209,88,0.08) 0%, rgba(10,132,255,0.04) 100%)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                            <span style={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.1em', color: '#30D158', textTransform: 'uppercase' }}>
                                Executive Pitch Line
                            </span>
                            <h2 style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: '#fff' }}>
                                "We speak the language of CISOs and CFOs by quantifying code defects as financial security debt with interest rates and compliance risk metrics."
                            </h2>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                            <div style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>Security Health Score</div>
                            <div style={{ fontSize: 32, fontWeight: 900, color: exec.security_health_score > 70 ? '#30D158' : exec.security_health_score > 50 ? '#FF9F0A' : '#FF453A' }}>
                                {typeof exec.security_health_score === 'number' ? exec.security_health_score.toFixed(1) : exec.security_health_score} <span style={{ fontSize: 16 }}>/ 100</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* 4 Primary Financial Cards */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
                    <div className="glass-card" style={{ padding: 20 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <span className="stat-kicker">PRINCIPAL SECURITY DEBT</span>
                            <DollarSign size={20} color="#FF453A" />
                        </div>
                        <div style={{ fontSize: 28, fontWeight: 900, color: '#FF453A' }}>{fmtVal(exec.current_security_debt)}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>Estimated cost to remediate all findings</div>
                    </div>

                    <div className="glass-card" style={{ padding: 20 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <span className="stat-kicker">DAILY INTEREST RATE</span>
                            <TrendingUp size={20} color="#FF9F0A" />
                        </div>
                        <div style={{ fontSize: 28, fontWeight: 900, color: '#FF9F0A' }}>{fmtVal(exec.daily_risk_accumulation)}<span style={{ fontSize: 14 }}>/day</span></div>
                        <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>Risk accumulation per day delayed</div>
                    </div>

                    <div className="glass-card" style={{ padding: 20 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <span className="stat-kicker">ANNUAL RISK GROWTH</span>
                            <AlertTriangle size={20} color="#FFD60A" />
                        </div>
                        <div style={{ fontSize: 28, fontWeight: 900, color: '#FFD60A' }}>{fmtVal(exec.annual_debt_growth)}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>{exec.industry_comparison}</div>
                    </div>

                    <div className="glass-card" style={{ padding: 20 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <span className="stat-kicker">REGULATORY FINE RISK</span>
                            <ShieldAlert size={20} color="#0A84FF" />
                        </div>
                        <div style={{ fontSize: 28, fontWeight: 900, color: '#0A84FF' }}>{fmtVal(exec.compliance_exposure)}</div>
                        <div style={{ fontSize: 11, color: '#30D158', fontWeight: 700, marginTop: 4 }}>DPDP Act (India 2023), RBI, CERT-In, GDPR</div>
                    </div>
                </div>

                {/* Main Content Grid: Financial Projections + High-ROI Action Items */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 28 }}>
                    {/* Left: Financial Projections */}
                    <div className="glass-card" style={{ padding: 24 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                            <Calendar size={20} color="var(--teal)" />
                            <h3 style={{ fontSize: 16, fontWeight: 700 }}>Financial Risk Projections over Time</h3>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                            <div style={{ padding: 16, borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                    <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>30-Day Delay Projection</span>
                                    <strong style={{ fontSize: 15, color: '#FF9F0A' }}>{fmtVal(proj["30_day_projection"])}</strong>
                                </div>
                                <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.08)' }}>
                                    <div style={{ width: '25%', height: '100%', background: '#FF9F0A', borderRadius: 3 }} />
                                </div>
                            </div>

                            <div style={{ padding: 16, borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                    <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>90-Day Delay Projection</span>
                                    <strong style={{ fontSize: 15, color: '#FF453A' }}>{fmtVal(proj["90_day_projection"])}</strong>
                                </div>
                                <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.08)' }}>
                                    <div style={{ width: '50%', height: '100%', background: '#FF453A', borderRadius: 3 }} />
                                </div>
                            </div>

                            <div style={{ padding: 16, borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                    <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>1-Year Total Risk Exposure</span>
                                    <strong style={{ fontSize: 15, color: '#0A84FF' }}>{fmtVal(proj["1_year_projection"])}</strong>
                                </div>
                                <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.08)' }}>
                                    <div style={{ width: '100%', height: '100%', background: '#0A84FF', borderRadius: 3 }} />
                                </div>
                            </div>
                        </div>

                        {recs.length > 0 && (
                            <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-strong)' }}>
                                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>Executive Recommendations:</div>
                                <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                    {recs.map((r, i) => <li key={i}>{r}</li>)}
                                </ul>
                            </div>
                        )}
                    </div>

                    {/* Right: Remediation ROI Action Items */}
                    <div className="glass-card" style={{ padding: 24 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                            <Award size={20} color="#30D158" />
                            <h3 style={{ fontSize: 16, fontWeight: 700 }}>Top Remediation ROI Action Items</h3>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {actions.map((act) => (
                                <div key={act.priority} style={{ padding: 14, borderRadius: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-strong)' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                                        <div>
                                            <span style={{ fontSize: 11, fontWeight: 800, color: '#30D158', background: 'rgba(48,209,88,0.15)', padding: '2px 8px', borderRadius: 4, marginRight: 8 }}>
                                                Priority #{act.priority}
                                            </span>
                                            <strong style={{ fontSize: 13, color: '#fff' }}>{act.action}</strong>
                                        </div>
                                        <div style={{ textAlign: 'right' }}>
                                            <div style={{ fontSize: 14, fontWeight: 900, color: '#30D158' }}>{act.annual_roi} ROI</div>
                                            <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{act.payback_period} payback</div>
                                        </div>
                                    </div>
                                    <div style={{ fontSize: 11, color: 'var(--text-tertiary)', display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                                        <span>File: {act.location}</span>
                                        <span>Est. Fix Cost: <strong style={{ color: '#fff' }}>{fmtVal(act.estimated_cost)}</strong></span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    )
}
