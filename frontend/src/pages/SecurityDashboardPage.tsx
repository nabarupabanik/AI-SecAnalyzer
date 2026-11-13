import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
    FileStack,
    ShieldAlert,
    GitBranch,
    Biohazard,
    Settings2,
    Package,
    AlertTriangle, ChevronRight, Timer, DollarSign, TrendingUp,
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import DashboardSidebar from '../components/DashboardSidebar'
import ExploitChainVisualization from '../components/ExploitChainVisualization'
import { explainRisk } from '../lib/riskExplain'
import { scanModeLabel } from '../lib/scanModeLabel'

/* ── Types (match API /api/scans/<id>) ─────────────────────── */
interface Vuln { file: string; line: number; type: string; severity: string; code: string }
interface ProcEv { file: string; line: number; type: string; function: string; risk: string; tainted: boolean }
interface MalInd { file: string; line: number; type: string; severity: string; evidence: string }
interface Tamper { file: string; line: number; type: string; risk: string; evidence: string; score: number }
interface Dependency { 
    dependency_name: string
    installed_version: string
    fixed_version: string | null
    vulnerability_id: string
    severity: string
    description: string
    references: string[]
    ecosystem: string
    file_path: string
}

interface ScanPayload {
    id: number
    project_path: string
    scan_mode: string
    file_count: number
    total_size_kb: number
    scan_time_ms?: number | null
    risk_score: number | null
    risk_level: string | null
    created_at: string | null
    languages: string[]
    files: unknown[]
    vulnerabilities: Vuln[]
    process_events: ProcEv[]
    malicious_indicators: MalInd[]
    process_graph: { nodes: string[]; edges: { from: string; to: string; file?: string | null }[] }
    tamperability: Tamper[]
    dependency_vulnerabilities?: Dependency[]
    exploit_chain_analysis?: {
        exploit_chains: any[]
        stg_graph: Record<string, any>
        ecg_graph: Record<string, any>
        statistics: Record<string, any>
        risk_impact: Record<string, any>
    }
    stg_summary?: { total_nodes: number; total_edges: number }
    ecg_summary?: { total_nodes: number; total_edges: number }
    constraint_satisfaction_stats?: Record<string, any>
    security_debt_analysis?: Record<string, any>
    exploit_chains?: any[]
    eliminated_paths_count?: number
    exploit_chain_score?: number
    stg_graph?: Record<string, any>
    ecg_graph?: Record<string, any>
    telemetry?: {
        duration_ms: number
        semgrep_cache_hit: boolean
        error: string
    } | null
}

const COLORS = {
    injection: '#FF453A',
    process: '#FF9F0A',
    malicious: '#FFD60A',
    tamper: '#D4A017',
    config: '#0A84FF',
    dependency: '#30D158',
}

function categorizeFindings(scan: ScanPayload) {
    const vulns = scan.vulnerabilities || []
    let injection = 0
    let configWeak = 0
    for (const v of vulns) {
        const t = (v.type || '').toLowerCase()
        if (
            t.includes('sql') ||
            t.includes('injection') ||
            t.includes('command') ||
            t.includes('unvalidated')
        )
            injection++
        else if (t.includes('secret') || t.includes('crypto') || t.includes('hash') || t.includes('file operation'))
            configWeak++
        else injection += 0.35
    }
    const proc = (scan.process_events || []).length
    const mal = (scan.malicious_indicators || []).length
    const tam = (scan.tamperability || []).length
    const deps = (scan.dependency_vulnerabilities || []).length
    const tamperCfg = (scan.tamperability || []).filter(
        x =>
            (x.type || '').toLowerCase().includes('config') ||
            (x.type || '').toLowerCase().includes('debug') ||
            (x.type || '').toLowerCase().includes('exposed'),
    ).length

    const raw = [
        { key: 'injection', label: 'Injection', value: injection + 1, color: COLORS.injection },
        { key: 'process', label: 'Process Risk', value: proc + 0.5, color: COLORS.process },
        { key: 'malicious', label: 'Malicious Behavior', value: mal + 0.5, color: COLORS.malicious },
        { key: 'tamper', label: 'Tamperability', value: tam + tamperCfg * 0.3, color: COLORS.tamper },
        { key: 'config', label: 'Config Weakness', value: configWeak + 0.5, color: COLORS.config },
        { key: 'dependency', label: 'Dependency Vulns', value: deps + 0.5, color: COLORS.dependency },
    ]
    const sum = raw.reduce((s, x) => s + x.value, 0)
    if (sum < 0.01) {
        return raw.map(r => ({ ...r, pct: 20, value: 20 }))
    }
    return raw.map(r => ({ ...r, pct: Math.round((100 * r.value) / sum) }))
}

function tamperScoreSum(t: Tamper[]) {
    return Math.min(100, (t || []).reduce((s, x) => s + (x.score || 0), 0))
}

function postureBars(scan: ScanPayload, riskScore: number) {
    const vn = scan.vulnerabilities?.length ?? 0
    const crit = (scan.vulnerabilities || []).filter(x => x.severity === 'Critical' || x.severity === 'High').length
    const codeQuality = Math.max(5, Math.min(100, 100 - vn * 4 - crit * 6))
    const tainted = (scan.process_events || []).filter(e => e.tainted).length
    const pe = (scan.process_events || []).length
    const processSafety = Math.max(5, Math.min(100, 100 - tainted * 10 - pe * 2))
    const ts = tamperScoreSum(scan.tamperability || [])
    const configSecurity = Math.max(5, Math.min(100, 100 - Math.min(ts, 80)))
    const aiConfidence = Math.max(60, Math.min(98, 72 + (100 - riskScore) * 0.28))
    return [
        { label: 'Code Quality', pct: Math.round(codeQuality), color: '#FF453A' },
        { label: 'Process Safety', pct: Math.round(processSafety), color: '#FF9F0A' },
        { label: 'Config Security', pct: Math.round(configSecurity), color: '#FFD60A' },
        { label: 'AI Confidence', pct: Math.round(aiConfidence), color: '#30D158' },
    ]
}

export default function SecurityDashboardPage() {
    const { scanId } = useParams<{ scanId: string }>()
    const navigate = useNavigate()
    const [scan, setScan] = useState<ScanPayload | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        if (!scanId) return
        let cancelled = false
        ;(async () => {
            try {
                const res = await fetch(`/api/scans/${scanId}`)
                const data = await res.json()
                if (!res.ok || data.status !== 'success') {
                    setError(data.error || 'Failed to load scan.')
                    return
                }
                if (!cancelled) setScan(data.scan as ScanPayload)
            } catch {
                if (!cancelled) setError('Cannot reach API server.')
            } finally {
                if (!cancelled) setLoading(false)
            }
        })()
        return () => {
            cancelled = true
        }
    }, [scanId])

    const pieData = useMemo(() => {
        if (!scan) return []
        const cats = categorizeFindings(scan)
        return cats.map(c => ({ name: c.label, value: c.pct, color: c.color }))
    }, [scan])

    const riskScore = scan?.risk_score ?? 0
    const riskLevel = (scan?.risk_level || 'Unknown').toUpperCase()
    const criticalVulns = scan
        ? scan.vulnerabilities.filter(v => v.severity === 'Critical' || v.severity === 'High').length
        : 0

    const posture = scan ? postureBars(scan, riskScore) : []

    const riskNarrative = useMemo(() => (scan ? explainRisk(scan) : null), [scan])

    const fmtDate = (iso: string | null) => {
        if (!iso) return '—'
        try {
            const d = new Date(iso)
            return d.toLocaleString(undefined, {
                dateStyle: 'medium',
                timeStyle: 'short',
            })
        } catch {
            return iso
        }
    }

    /** Match mock: `/project/my-application` — normalize slashes; keep full path readable on Windows. */
    const projectPathDisplay = scan?.project_path
        ? scan.project_path.replace(/\\/g, '/')
        : '—'

    const durationMs =
        scan && scan.scan_time_ms != null && scan.scan_time_ms > 0
            ? scan.scan_time_ms
            : scan?.telemetry != null && scan.telemetry.duration_ms > 0
              ? scan.telemetry.duration_ms
              : null

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading dashboard…
            </div>
        )
    }

    if (error || !scan || !scanId) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: 40 }}>
                <p style={{ color: '#FF453A', marginBottom: 16 }}>{error || 'Scan not found.'}</p>
                <button className="btn-ghost" onClick={() => navigate('/')}>
                    Back to Home
                </button>
            </div>
        )
    }

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: 'var(--text-primary)' }}>
            <DashboardSidebar scanId={scanId} active="dashboard" />

            {/* Main */}
            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px' }}>
                <header style={{ marginBottom: 28 }}>
                    <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Security Dashboard</h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', columnGap: 10, rowGap: 8 }}>
                        <span>
                            Scan completed — {fmtDate(scan.created_at)} | {projectPathDisplay}
                        </span>
                        <span className="scan-mode-badge">{scanModeLabel(scan.scan_mode)}</span>
                    </p>
                </header>

                {/* Financial Security Debt Banner */}
                {scan.security_debt_analysis?.executive_summary && (
                    <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 24, borderLeft: '4px solid #30D158', background: 'linear-gradient(135deg, rgba(48,209,88,0.08) 0%, rgba(10,132,255,0.04) 100%)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(48,209,88,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <DollarSign size={24} color="#30D158" />
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.08em', color: '#30D158', textTransform: 'uppercase' }}>FINANCIAL SECURITY DEBT PORTFOLIO & ROI</div>
                                <div style={{ fontSize: 20, fontWeight: 900, color: '#fff', marginTop: 2 }}>
                                    {scan.security_debt_analysis.executive_summary.current_security_debt} <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-tertiary)' }}>Principal Debt</span>
                                    <span style={{ margin: '0 12px', color: 'var(--border-strong)' }}>|</span>
                                    <span style={{ color: '#FF9F0A' }}>{scan.security_debt_analysis.executive_summary.daily_risk_accumulation}/day</span> <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-tertiary)' }}>Daily Interest Rate</span>
                                </div>
                            </div>
                        </div>
                        <Link to={`/dashboard/${scanId}/security-debt`} style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, background: '#30D158', color: '#000', fontWeight: 700, fontSize: 13 }}>
                            View ROI Engine <ChevronRight size={16} />
                        </Link>
                    </div>
                )}

                {/* Top metrics */}
                <div id="top" style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14, marginBottom: 28 }}>
                    {[
                        { label: 'Total Files', val: scan.file_count, sub: 'indexed', icon: FileStack, c: 'var(--blue)' },
                        { label: 'Vulnerabilities', val: scan.vulnerabilities.length, sub: `${criticalVulns} critical`, icon: ShieldAlert, c: '#FF453A' },
                        { label: 'Process Events', val: scan.process_events.length, sub: 'risk events', icon: GitBranch, c: '#FF9F0A' },
                        { label: 'Malicious Indicators', val: scan.malicious_indicators.length, sub: 'patterns found', icon: Biohazard, c: '#FF453A' },
                        { label: 'Dependency Vulns', val: scan.dependency_vulnerabilities?.length || 0, sub: 'third-party libs', icon: Package, c: '#30D158' },
                    ].map(m => (
                        <div key={m.label} className="glass-card" style={{ padding: '18px 16px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                                <span className="stat-kicker">{m.label}</span>
                                <m.icon size={20} color={m.c} />
                            </div>
                            <div style={{ fontSize: 28, fontWeight: 900, color: m.c }}>{m.val}</div>
                            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>{m.sub}</div>
                        </div>
                    ))}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: 20, alignItems: 'start' }}>
                    {/* Left: risk donut + Security Posture */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div className="glass-card" style={{ padding: 24 }} id="risk-distribution">
                            <div style={{ marginBottom: 20 }}>
                                <div style={{ fontSize: 16, fontWeight: 700 }}>Risk Distribution</div>
                                <div style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 4 }}>By vulnerability category</div>
                            </div>
                            <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
                                <div style={{ width: 220, height: 220, position: 'relative' }}>
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie
                                                data={pieData}
                                                cx="50%"
                                                cy="50%"
                                                innerRadius={68}
                                                outerRadius={96}
                                                paddingAngle={2}
                                                dataKey="value"
                                            >
                                                {pieData.map((_, i) => (
                                                    <Cell key={i} fill={pieData[i].color} stroke="rgba(0,0,0,0.3)" strokeWidth={1} />
                                                ))}
                                            </Pie>
                                        </PieChart>
                                    </ResponsiveContainer>
                                    <div style={{
                                        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                                        alignItems: 'center', justifyContent: 'center', pointerEvents: 'none',
                                    }}>
                                        <span style={{ fontSize: 28, fontWeight: 900, color: '#fff' }}>{riskScore}</span>
                                        <span className="stat-kicker" style={{ letterSpacing: '0.08em' }}>RISK SCORE</span>
                                    </div>
                                </div>
                                <div style={{ flex: 1, minWidth: 200 }}>
                                    {pieData.map(row => (
                                        <div key={row.name} style={{ marginBottom: 12 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                                <span style={{ width: 8, height: 8, borderRadius: '50%', background: row.color }} />
                                                <span style={{ flex: 1, fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{row.name}</span>
                                                <span style={{ fontSize: 13, fontWeight: 700 }}>{row.value}%</span>
                                            </div>
                                            <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
                                                <div style={{ width: `${row.value}%`, height: '100%', background: row.color, borderRadius: 3 }} />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="glass-card" style={{ padding: 22 }}>
                            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 4 }}>Security Posture</div>
                            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
                                Overall Security Posture:{' '}
                                <span style={{ color: '#FF9F0A', fontWeight: 600 }}>{scan.risk_level || 'Unknown'} Risk</span>
                            </div>
                            {posture.map(p => (
                                <div key={p.label} style={{ marginBottom: 14 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6 }}>
                                        <span>{p.label}</span>
                                        <span style={{ fontWeight: 700 }}>{p.pct}%</span>
                                    </div>
                                    <div style={{ height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.06)' }}>
                                        <div style={{ width: `${p.pct}%`, height: '100%', borderRadius: 4, background: p.color }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Right: risk summary, narrative, performance, quick nav */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div className="glass-card" style={{ padding: 22 }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                                <AlertTriangle size={28} color="#FF9F0A" />
                                <div>
                                    <div className="stat-kicker" style={{ letterSpacing: '0.08em' }}>OVERALL RISK SCORE</div>
                                    <div style={{ fontSize: 36, fontWeight: 900, marginTop: 4 }}>
                                        {riskScore} <span style={{ fontSize: 18, color: 'var(--text-tertiary)' }}>/ 100</span>
                                    </div>
                                    <span style={{
                                        display: 'inline-block', marginTop: 10, padding: '6px 14px', borderRadius: 999,
                                        fontSize: 12, fontWeight: 800,
                                        background: riskLevel.includes('HIGH') || riskLevel.includes('CRITICAL')
                                            ? 'rgba(255,69,58,0.2)' : riskLevel.includes('MEDIUM')
                                                ? 'rgba(255,159,10,0.2)' : 'rgba(48,209,88,0.2)',
                                        color: riskLevel.includes('HIGH') || riskLevel.includes('CRITICAL')
                                            ? '#FF453A' : riskLevel.includes('MEDIUM') ? '#FF9F0A' : '#30D158',
                                    }}>
                                        {scan.risk_level || 'UNKNOWN'} RISK
                                    </span>
                                </div>
                            </div>
                        </div>

                        {riskNarrative && (
                            <div className="glass-card" style={{ padding: 22 }}>
                                <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 12 }}>Why this risk score?</div>
                                {riskNarrative.lines.map((line, i) => (
                                    <p
                                        key={i}
                                        style={{
                                            fontSize: 13,
                                            color: 'var(--text-secondary)',
                                            lineHeight: 1.55,
                                            marginBottom: i < riskNarrative.lines.length - 1 ? 10 : 0,
                                        }}
                                    >
                                        {line}
                                    </p>
                                ))}
                            </div>
                        )}

                        <div className="glass-card" style={{ padding: 22 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                                <Timer size={20} color="var(--teal)" />
                                <div style={{ fontSize: 15, fontWeight: 700 }}>Performance</div>
                            </div>
                            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <div>
                                    <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Scan duration</strong>
                                    {' — '}
                                    {durationMs == null
                                        ? 'Not recorded for this scan.'
                                        : (() => {
                                              const s = (durationMs / 1000).toFixed(durationMs >= 10000 ? 0 : 1)
                                              return `${Math.round(durationMs).toLocaleString()} ms (~${s}s)`
                                          })()}
                                </div>
                                {scan.file_count > 0 && durationMs != null ? (
                                    <div style={{ marginTop: 8 }}>
                                        <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Throughput</strong>
                                        {' — '}
                                        ~{((scan.file_count / durationMs) * 1000).toFixed(1)} files/sec
                                    </div>
                                ) : null}
                                <div style={{ marginTop: 8 }}>
                                    <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Semgrep</strong>
                                    {' — '}
                                    {scan.telemetry == null
                                        ? 'No telemetry row (older scan or DB outside worker path).'
                                        : scan.telemetry.semgrep_cache_hit
                                          ? 'Incremental cache hit — rules skipped for unchanged manifest.'
                                          : 'Fresh Semgrep contribution recorded for this run.'}
                                </div>
                                {scan.telemetry?.error ? (
                                    <div style={{ marginTop: 8, color: '#FF453A', fontSize: 12 }}>{scan.telemetry.error}</div>
                                ) : null}
                            </div>
                        </div>

                        {/* Exploit Chain Analysis - Patent Critical */}
                        {(scan?.exploit_chains || scan?.exploit_chain_analysis) && (
                            <ExploitChainVisualization
                                chains={scan?.exploit_chains || scan?.exploit_chain_analysis?.exploit_chains || []}
                                statistics={{
                                    total_chains: scan?.exploit_chains?.length || scan?.exploit_chain_analysis?.statistics?.total_chains || 0,
                                    confirmed_chains: scan?.exploit_chains?.filter((c: any) => c.feasibility === 'confirmed')?.length || scan?.exploit_chain_analysis?.statistics?.confirmed_chains || 0,
                                    eliminated_paths: scan?.eliminated_paths_count || scan?.exploit_chain_analysis?.statistics?.eliminated_paths || scan?.constraint_satisfaction_stats?.eliminated_paths_count || 0,
                                    elimination_rate: (scan?.eliminated_paths_count || scan?.exploit_chain_analysis?.statistics?.eliminated_paths || 0) > 0 ? 1.0 : 0,
                                    constraint_satisfaction_rate: scan?.constraint_satisfaction_stats?.elimination_rate ?? scan?.exploit_chain_analysis?.statistics?.elimination_rate ?? scan?.ecg_graph?.statistics?.constraint_satisfaction_rate ?? 0,
                                    total_vulnerabilities: scan?.vulnerabilities?.length || 0,
                                    stg_nodes: scan?.stg_summary?.total_nodes || scan?.stg_graph?.summary?.total_nodes || scan?.exploit_chain_analysis?.statistics?.stg_nodes || 0,
                                    data_flow_constraints_satisfied: scan?.constraint_satisfaction_stats?.data_flow_constraints_satisfied ?? scan?.exploit_chain_analysis?.statistics?.data_flow_constraints_satisfied ?? scan?.ecg_graph?.statistics?.data_flow_constraints_satisfied ?? 0,
                                    data_flow_constraints_total: scan?.constraint_satisfaction_stats?.data_flow_constraints_total ?? scan?.exploit_chain_analysis?.statistics?.data_flow_constraints_total ?? scan?.ecg_graph?.statistics?.data_flow_constraints_total ?? 0,
                                    execution_order_constraints_satisfied: scan?.constraint_satisfaction_stats?.execution_order_constraints_satisfied ?? scan?.exploit_chain_analysis?.statistics?.execution_order_constraints_satisfied ?? scan?.ecg_graph?.statistics?.execution_order_constraints_satisfied ?? 0,
                                    execution_order_constraints_total: scan?.constraint_satisfaction_stats?.execution_order_constraints_total ?? scan?.exploit_chain_analysis?.statistics?.execution_order_constraints_total ?? scan?.ecg_graph?.statistics?.execution_order_constraints_total ?? 0,
                                    privilege_constraints_satisfied: scan?.constraint_satisfaction_stats?.privilege_constraints_satisfied ?? scan?.exploit_chain_analysis?.statistics?.privilege_constraints_satisfied ?? scan?.ecg_graph?.statistics?.privilege_constraints_satisfied ?? 0,
                                    privilege_constraints_total: scan?.constraint_satisfaction_stats?.privilege_constraints_total ?? scan?.exploit_chain_analysis?.statistics?.privilege_constraints_total ?? scan?.ecg_graph?.statistics?.privilege_constraints_total ?? 0
                                }}
                                onChainSelect={(chain) => {
                                    console.log('Selected exploit chain:', chain)
                                    // TODO: Navigate to detailed chain analysis page
                                }}
                            />
                        )}

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
                            {[
                                { label: 'Vulnerabilities', to: `/dashboard/${scanId}/vulnerabilities`, bg: 'rgba(255,69,58,0.25)', border: 'rgba(255,69,58,0.4)' },
                                { label: 'Process Graph', to: `/dashboard/${scanId}/process-graph`, bg: 'rgba(10,132,255,0.2)', border: 'rgba(10,132,255,0.35)' },
                                { label: 'Malicious', to: `/dashboard/${scanId}/malicious`, bg: 'rgba(255,159,10,0.2)', border: 'rgba(255,159,10,0.35)' },
                                { label: 'Tamperability', to: `/dashboard/${scanId}/tamperability`, bg: 'rgba(212,160,23,0.18)', border: 'rgba(255,214,10,0.35)' },
                                { label: 'Reports', to: `/dashboard/${scanId}/reports`, bg: 'rgba(48,209,88,0.2)', border: 'rgba(48,209,88,0.35)' },
                            ].map(q => (
                                <Link
                                    key={q.label}
                                    to={q.to}
                                    style={{
                                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                        padding: '14px 16px', borderRadius: 12, textDecoration: 'none', color: '#fff',
                                        fontSize: 14, fontWeight: 600,
                                        background: q.bg, border: `1px solid ${q.border}`,
                                        gridColumn: q.label === 'Reports' ? '1 / -1' : undefined,
                                    }}
                                >
                                    {q.label} <ChevronRight size={16} />
                                </Link>
                            ))}
                        </div>
                    </div>
                </div>

            </main>
        </div>
    )
}
