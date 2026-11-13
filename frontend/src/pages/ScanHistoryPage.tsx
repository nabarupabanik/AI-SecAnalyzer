import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus, ExternalLink, ShieldAlert, ShieldOff, ShieldCheck } from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'
import { formatReportId } from '../lib/reportSummary'

interface ScanListItem {
    id: number
    project_path: string
    scan_mode: string
    file_count: number
    created_at: string | null
    risk_score: number | null
    risk_level: string | null
    vulnerability_count: number
    critical_count: number
}

interface ListResponse {
    status: string
    total: number
    scans: ScanListItem[]
}

function scanModeLabel(mode: string): string {
    const m = (mode || '').toLowerCase()
    if (m === 'behavioral') return 'Behavioral Deep Scan'
    if (m === 'full') return 'Full Intelligence Scan'
    if (m === 'basic') return 'Basic Scan'
    return mode || 'Scan'
}

function riskScoreColor(score: number | null): { bg: string; fg: string } {
    if (score == null) return { bg: 'rgba(245,245,247,0.10)', fg: 'var(--text-secondary)' }
    if (score >= 70) return { bg: 'rgba(255,69,58,0.2)', fg: '#FF453A' }
    if (score >= 40) return { bg: 'rgba(255,159,10,0.18)', fg: '#FF9F0A' }
    return { bg: 'rgba(48,209,88,0.15)', fg: '#30D158' }
}

function riskBadge(level: string | null): { label: string; Icon: typeof ShieldAlert; color: string } {
    const l = (level || '').toLowerCase()
    if (l.includes('high') || l.includes('critical'))
        return { label: `${level || 'High'} Risk`, Icon: ShieldAlert, color: '#FF453A' }
    if (l.includes('medium'))
        return { label: `${level || 'Medium'} Risk`, Icon: ShieldOff, color: '#FF9F0A' }
    if (l.includes('low'))
        return { label: `${level || 'Low'} Risk`, Icon: ShieldCheck, color: '#30D158' }
    return { label: level || 'Unknown', Icon: ShieldOff, color: 'var(--text-secondary)' }
}

function fmtDateTime(iso: string | null): string {
    if (!iso) return '—'
    try {
        return new Date(iso).toLocaleString(undefined, {
            dateStyle: 'medium',
            timeStyle: 'medium',
        })
    } catch {
        return iso
    }
}

export default function ScanHistoryPage() {
    const navigate = useNavigate()
    const [data, setData] = useState<ListResponse | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        let cancelled = false
        ;(async () => {
            try {
                const res = await fetch('/api/scans?limit=100')
                const json = (await res.json()) as ListResponse
                if (!res.ok || json.status !== 'success') {
                    setError('Failed to load scan history.')
                    return
                }
                if (!cancelled) setData(json)
            } catch {
                if (!cancelled) setError('Cannot reach API server.')
            } finally {
                if (!cancelled) setLoading(false)
            }
        })()
        return () => {
            cancelled = true
        }
    }, [])

    const scans = data?.scans ?? []
    const firstScanId = scans[0]?.id

    const stats = useMemo(() => {
        if (!scans.length) return { avgRisk: 0, totalVulns: 0 }
        const withRisk = scans.filter(s => s.risk_score != null)
        const avgRisk =
            withRisk.length > 0
                ? Math.round(withRisk.reduce((a, s) => a + (s.risk_score ?? 0), 0) / withRisk.length)
                : 0
        const totalVulns = scans.reduce((a, s) => a + (s.vulnerability_count ?? 0), 0)
        return { avgRisk, totalVulns }
    }, [scans])

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading scan history…
            </div>
        )
    }

    if (error) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: 40 }}>
                <p style={{ color: '#FF453A', marginBottom: 16 }}>{error}</p>
                <button className="btn-ghost" onClick={() => navigate('/')}>Back to Home</button>
            </div>
        )
    }

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: '#F5F5F7' }}>
            <DashboardSidebar
                scanId={firstScanId != null ? String(firstScanId) : '0'}
                active="scan-history"
                noScanContext={scans.length === 0}
            />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px', minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
                    <div>
                        <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Scan History</h1>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                            {data?.total ?? 0} scan{(data?.total ?? 0) === 1 ? '' : 's'} completed · All results archived
                        </p>
                    </div>
                    <Link to="/scan" className="btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, textDecoration: 'none' }}>
                        <Plus size={18} /> New Scan
                    </Link>
                </div>

                {/* Summary bar */}
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 32,
                        padding: '18px 22px',
                        borderRadius: 12,
                        background: '#161b22',
                        border: '1px solid rgba(255,255,255,0.08)',
                        marginBottom: 22,
                    }}
                >
                    <div>
                        <div className="stat-kicker">TOTAL SCANS</div>
                        <div style={{ fontSize: 26, fontWeight: 900, color: '#0A84FF' }}>{data?.total ?? 0}</div>
                    </div>
                    <div>
                        <div className="stat-kicker">AVG RISK SCORE</div>
                        <div style={{ fontSize: 26, fontWeight: 900, color: '#FF9F0A' }}>{scans.length ? stats.avgRisk : '—'}</div>
                    </div>
                    <div>
                        <div className="stat-kicker">TOTAL VULNERABILITIES</div>
                        <div style={{ fontSize: 26, fontWeight: 900, color: '#FF453A' }}>{stats.totalVulns}</div>
                    </div>
                </div>

                {scans.length === 0 ? (
                    <div
                        style={{
                            padding: 40,
                            textAlign: 'center',
                            borderRadius: 12,
                            background: '#161b22',
                            border: '1px solid var(--border)',
                            color: 'var(--text-secondary)',
                        }}
                    >
                        No scans yet.{' '}
                        <Link to="/scan" style={{ color: '#0A84FF' }}>Start a new scan</Link> to see history here.
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {scans.map(s => {
                            const rc = riskScoreColor(s.risk_score)
                            const riskMeta = riskBadge(s.risk_level)
                            const RiskIcon = riskMeta.Icon
                            const reportId = formatReportId(s.id, s.created_at)
                            const pathShort = s.project_path.replace(/\\/g, '/')
                            return (
                                <div
                                    key={s.id}
                                    style={{
                                        display: 'flex',
                                        flexWrap: 'wrap',
                                        gap: 16,
                                        alignItems: 'center',
                                        justifyContent: 'space-between',
                                        padding: '16px 18px',
                                        borderRadius: 12,
                                        background: '#161b22',
                                        border: '1px solid rgba(255,255,255,0.08)',
                                    }}
                                >
                                    <div
                                        style={{
                                            width: 88,
                                            height: 72,
                                            borderRadius: 10,
                                            display: 'flex',
                                            flexDirection: 'column',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            background: rc.bg,
                                            border: `1px solid ${rc.fg}33`,
                                        }}
                                    >
                                        <span style={{ fontSize: 22, fontWeight: 900, color: rc.fg }}>
                                            {s.risk_score ?? '—'}
                                        </span>
                                        <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)' }}>/100</span>
                                    </div>

                                    <div style={{ minWidth: 0, flex: '1 1 220px' }}>
                                        <div style={{ fontSize: 13, fontWeight: 800, marginBottom: 6 }}>{reportId}</div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
                                            <RiskIcon size={14} color={riskMeta.color} />
                                            <span style={{ fontSize: 12, fontWeight: 700, color: riskMeta.color }}>{riskMeta.label}</span>
                                        </div>
                                        <div style={{ fontSize: 13, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{pathShort}</div>
                                        <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginTop: 4 }}>
                                            {fmtDateTime(s.created_at)} · {scanModeLabel(s.scan_mode)}
                                        </div>
                                    </div>

                                    <div style={{ textAlign: 'right', minWidth: 100 }}>
                                        <div style={{ fontSize: 18, fontWeight: 900, color: '#FF453A' }}>{s.critical_count}</div>
                                        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)' }}>Critical</div>
                                        <div style={{ fontSize: 14, fontWeight: 800, marginTop: 6, color: '#f5f5f7' }}>{s.vulnerability_count}</div>
                                        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)' }}>Total</div>
                                    </div>

                                    <Link
                                        to={`/dashboard/${s.id}/reports`}
                                        className="btn-primary"
                                        style={{
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: 6,
                                            padding: '10px 14px',
                                            borderRadius: 10,
                                            fontSize: 13,
                                            fontWeight: 600,
                                            textDecoration: 'none',
                                            whiteSpace: 'nowrap',
                                        }}
                                    >
                                        Open Report <ExternalLink size={15} />
                                    </Link>
                                </div>
                            )
                        })}
                    </div>
                )}
            </main>
        </div>
    )
}
