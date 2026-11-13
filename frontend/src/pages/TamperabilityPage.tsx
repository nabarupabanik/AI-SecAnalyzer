import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
    FolderOpen, Cpu, AlertOctagon, ShieldAlert, FileWarning, Settings2,
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import DashboardSidebar from '../components/DashboardSidebar'
import {
    type TamperIssue,
    groupTamperIssues,
    tamperResistancePct,
    resistanceLabel,
    runtimeManipulationBars,
    assessmentSummary,
    severityStyleTamper,
} from '../lib/tamperDisplay'

interface ScanPayload {
    id: number
    risk_score: number | null
    risk_level: string | null
    tamperability: TamperIssue[]
}

function pickIcon(type: string) {
    const t = type.toLowerCase()
    if (t.includes('exposed') || t.includes('config')) return FolderOpen
    if (t.includes('debug')) return AlertOctagon
    if (t.includes('admin') || t.includes('role')) return ShieldAlert
    if (t.includes('writable')) return FileWarning
    if (t.includes('environment')) return Cpu
    return Settings2
}

export default function TamperabilityPage() {
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

    const issues = scan?.tamperability ?? []
    const resistancePct = useMemo(() => tamperResistancePct(issues), [issues])
    const resistMeta = useMemo(() => resistanceLabel(resistancePct), [resistancePct])
    const groups = useMemo(() => groupTamperIssues(issues), [issues])
    const runtimeBars = useMemo(
        () => runtimeManipulationBars(issues, scan?.risk_score ?? null),
        [issues, scan?.risk_score],
    )
    const summaryHtml = useMemo(
        () => assessmentSummary(resistancePct, issues, scan?.risk_level ?? null),
        [resistancePct, issues, scan?.risk_level],
    )

    const pieData = useMemo(
        () => [
            { name: 'resistance', value: resistancePct, fill: resistMeta.color },
            { name: 'gap', value: 100 - resistancePct, fill: 'rgba(255,255,255,0.08)' },
        ],
        [resistancePct, resistMeta.color],
    )

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading tamperability assessment…
            </div>
        )
    }

    if (error || !scan || !scanId) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: 40 }}>
                <p style={{ color: '#FF453A', marginBottom: 16 }}>{error || 'Scan not found.'}</p>
                <button className="btn-ghost" onClick={() => navigate('/')}>Back to Home</button>
            </div>
        )
    }

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: '#F5F5F7' }}>
            <DashboardSidebar scanId={scanId} active="tamperability" />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 36px 48px', minWidth: 0 }}>
                <header style={{ marginBottom: 28 }}>
                    <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Tamperability Assessment</h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                        Evaluating runtime manipulation risks and integrity protection mechanisms.
                    </p>
                </header>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'flex-start' }}>
                    {/* Left: findings */}
                    <div style={{ flex: '1 1 480px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
                        {issues.length === 0 ? (
                            <div
                                style={{
                                    padding: 28,
                                    borderRadius: 12,
                                    background: '#161b22',
                                    border: '1px solid rgba(255,255,255,0.06)',
                                    color: 'var(--text-secondary)',
                                }}
                            >
                                No tamperability issues detected for this scan.
                            </div>
                        ) : (
                            groups.map(g => {
                                const Icon = pickIcon(g.type)
                                const sev = severityStyleTamper(g.maxRisk)
                                return (
                                    <div
                                        key={g.type}
                                        style={{
                                            borderRadius: 12,
                                            background: '#161b22',
                                            border: '1px solid rgba(255,255,255,0.08)',
                                            padding: '16px 18px',
                                        }}
                                    >
                                        <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                                            <div
                                                style={{
                                                    width: 44,
                                                    height: 44,
                                                    borderRadius: 8,
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    justifyContent: 'center',
                                                    background: 'rgba(30,35,45,0.95)',
                                                    border: '1px solid rgba(255,255,255,0.1)',
                                                    flexShrink: 0,
                                                }}
                                            >
                                                <Icon size={22} color="var(--text-primary)" />
                                            </div>
                                            <div style={{ flex: 1, minWidth: 0 }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
                                                    <span style={{ fontWeight: 700, fontSize: 15 }}>{g.type}</span>
                                                    <span
                                                        style={{
                                                            fontSize: 11,
                                                            fontWeight: 800,
                                                            padding: '3px 10px',
                                                            borderRadius: 999,
                                                            background: sev.bg,
                                                            color: sev.color,
                                                        }}
                                                    >
                                                        {g.maxRisk}
                                                    </span>
                                                    <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                                                        {g.count} instance{g.count === 1 ? '' : 's'}
                                                    </span>
                                                </div>
                                                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                                                    <strong style={{ color: 'var(--text-secondary)' }}>Why this is tamperable:</strong>{' '}
                                                    {g.description}
                                                </p>
                                                <ul style={{ marginTop: 10, paddingLeft: 18, fontSize: 12, color: 'var(--text-tertiary)', fontFamily: 'ui-monospace, monospace' }}>
                                                    {g.items.slice(0, 6).map((it, idx) => (
                                                        <li key={idx} style={{ marginBottom: 4 }}>
                                                            {it.file.replace(/\\/g, '/')}:{it.line} (score {it.score}, {it.risk})
                                                        </li>
                                                    ))}
                                                    {g.items.length > 6 && (
                                                        <li style={{ listStyle: 'none', marginLeft: -18 }}>… {g.items.length - 6} more</li>
                                                    )}
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                )
                            })
                        )}
                    </div>

                    {/* Right: metrics */}
                    <div style={{ flex: '0 1 320px', width: '100%', maxWidth: 360, display: 'flex', flexDirection: 'column', gap: 16, position: 'sticky', top: 24 }}>
                        <div
                            style={{
                                borderRadius: 14,
                                background: '#161b22',
                                border: '1px solid rgba(255,255,255,0.08)',
                                padding: 20,
                            }}
                        >
                            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, color: 'var(--text-secondary)' }}>Tamper Resistance</div>
                            <div style={{ width: 200, height: 200, margin: '0 auto', position: 'relative' }}>
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie
                                            data={pieData}
                                            cx="50%"
                                            cy="50%"
                                            innerRadius={62}
                                            outerRadius={88}
                                            paddingAngle={2}
                                            dataKey="value"
                                            stroke="none"
                                        >
                                            {pieData.map((_, i) => (
                                                <Cell key={i} fill={pieData[i].fill} />
                                            ))}
                                        </Pie>
                                    </PieChart>
                                </ResponsiveContainer>
                                <div
                                    style={{
                                        position: 'absolute',
                                        inset: 0,
                                        display: 'flex',
                                        flexDirection: 'column',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        pointerEvents: 'none',
                                    }}
                                >
                                    <span style={{ fontSize: 28, fontWeight: 900, color: resistMeta.color }}>{resistancePct}%</span>
                                    <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', marginTop: 4 }}>RESISTANCE</span>
                                </div>
                            </div>
                            <div style={{ textAlign: 'center', marginTop: 8 }}>
                                <span
                                    style={{
                                        display: 'inline-block',
                                        padding: '6px 14px',
                                        borderRadius: 999,
                                        fontSize: 12,
                                        fontWeight: 800,
                                        background: resistMeta.badgeBg,
                                        color: resistMeta.color,
                                    }}
                                >
                                    {resistMeta.text}
                                </span>
                            </div>
                        </div>

                        <div
                            style={{
                                borderRadius: 14,
                                background: '#161b22',
                                border: '1px solid rgba(255,255,255,0.08)',
                                padding: 20,
                            }}
                        >
                            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 14, color: 'var(--text-secondary)' }}>
                                Runtime Manipulation Score
                            </div>
                            {runtimeBars.map((b) => (
                                <div key={b.label} style={{ marginBottom: 12 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                                        <span style={{ color: 'var(--text-secondary)' }}>{b.label}</span>
                                        <span style={{ fontWeight: 800, color: b.color }}>{b.pct}%</span>
                                    </div>
                                    <div style={{ height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.06)' }}>
                                        <div style={{ width: `${b.pct}%`, height: '100%', borderRadius: 4, background: b.color }} />
                                    </div>
                                </div>
                            ))}
                        </div>

                        <div
                            style={{
                                borderRadius: 14,
                                background: 'rgba(50,20,22,0.45)',
                                border: '1px solid rgba(255,69,58,0.25)',
                                padding: 16,
                            }}
                        >
                            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '0.1em', color: 'var(--text-secondary)', marginBottom: 8 }}>
                                ASSESSMENT SUMMARY
                            </div>
                            <p style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--text-secondary)' }}>
                                {summaryHtml.split(/\*\*(.*?)\*\*/g).map((part, i) =>
                                    i % 2 === 1 ? (
                                        <strong key={i} style={{ color: '#f5f5f7' }}>{part}</strong>
                                    ) : (
                                        <span key={i}>{part}</span>
                                    ),
                                )}
                            </p>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    )
}
