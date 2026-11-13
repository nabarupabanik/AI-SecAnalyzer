import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
    Terminal, Code, Wifi, Eye, AlertTriangle, ChevronDown, ChevronUp, Bug,
} from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'
import { maliciousCategory, maliciousRiskScore, severityAccent } from '../lib/maliciousDisplay'

interface MalInd {
    file: string
    line: number
    type: string
    severity: string
    evidence: string
}

function deriveMaliciousBadges(row: { type: string; evidence?: string }): string[] {
    const s = `${row.type || ''} ${row.evidence || ''}`.toLowerCase()
    const out: string[] = []
    if (s.includes('cross_file=true') || s.includes('cross-file') || s.includes('cross_file')) out.push('cross-file')
    if (s.includes('interprocedural') || s.includes('wrapper=')) out.push('interprocedural')
    if (s.includes('correlation') || s.includes('behavior_chain_score=')) out.push('correlated')
    if (s.includes('sanitized=true')) out.push('sanitized')
    if (s.includes('confidence=high')) out.push('high-confidence')
    return Array.from(new Set(out))
}

interface ScanPayload {
    id: number
    malicious_indicators: MalInd[]
}

function pickIcon(type: string) {
    const t = type.toLowerCase()
    if (t.includes('shell') || t.includes('reverse')) return Terminal
    if (t.includes('base64') || t.includes('exec') || t.includes('eval') || t.includes('decode')) return Code
    if (t.includes('ip') || t.includes('network') || t.includes('connect') || t.includes('socket')) return Wifi
    if (t.includes('obfuscat')) return Eye
    if (t.includes('pattern') || t.includes('correlation')) return Bug
    return AlertTriangle
}

export default function MaliciousAnalysisPage() {
    const { scanId } = useParams<{ scanId: string }>()
    const navigate = useNavigate()
    const [scan, setScan] = useState<ScanPayload | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [loading, setLoading] = useState(true)
    const [expanded, setExpanded] = useState<number | null>(null)

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

    const rows = useMemo(() => {
        if (!scan?.malicious_indicators?.length) return []
        return scan.malicious_indicators.map((m, i) => ({
            ...m,
            _i: i,
            category: maliciousCategory(m.type),
            risk: maliciousRiskScore(m.severity, m.type, m.file, m.line),
            Icon: pickIcon(m.type),
            badges: deriveMaliciousBadges(m),
        }))
    }, [scan])

    const criticalCount = useMemo(
        () => rows.filter(r => r.severity === 'Critical').length,
        [rows],
    )

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading malicious analysis…
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
            <DashboardSidebar scanId={scanId} active="malicious" />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px', maxWidth: 980 }}>
                <header style={{ marginBottom: 24 }}>
                    <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>
                        Malicious Behavior Intelligence
                    </h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                        {rows.length} malicious pattern{rows.length === 1 ? '' : 's'} identified
                        {criticalCount > 0 ? ` · ${criticalCount} critical threat${criticalCount === 1 ? '' : 's'}` : ''}
                    </p>
                </header>

                {criticalCount > 0 && (
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: 12,
                            padding: '12px 16px',
                            borderRadius: 10,
                            background: 'rgba(80,25,28,0.45)',
                            border: '1px solid rgba(255,69,58,0.35)',
                            marginBottom: 16,
                        }}
                    >
                        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#FF453A', marginTop: 6, flexShrink: 0 }} />
                        <p style={{ fontSize: 14, color: 'rgba(245,245,247,0.88)', lineHeight: 1.5 }}>
                            <strong style={{ color: '#FF6B65' }}>{criticalCount} critical pattern{criticalCount === 1 ? '' : 's'}</strong>
                            {' '}require immediate remediation. Reverse shell and dynamic code execution vectors present active exploitation risk.
                        </p>
                    </div>
                )}

                {rows.length === 0 ? (
                    <div
                        style={{
                            padding: 32,
                            borderRadius: 12,
                            background: '#161b22',
                            border: '1px solid rgba(255,255,255,0.06)',
                            color: 'var(--text-secondary)',
                            textAlign: 'center',
                        }}
                    >
                        No malicious indicators detected for this scan.
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {rows.map(({ _i, Icon, severity, type, file, line, category, risk, evidence, badges }) => {
                            const accent = severityAccent(severity)
                            const open = expanded === _i
                            return (
                                <div
                                    key={`${_i}-${file}-${line}`}
                                    style={{
                                        borderRadius: 12,
                                        background: '#161b22',
                                        border: '1px solid rgba(255,255,255,0.08)',
                                        overflow: 'hidden',
                                    }}
                                >
                                    <button
                                        type="button"
                                        onClick={() => setExpanded(open ? null : _i)}
                                        style={{
                                            width: '100%',
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: 14,
                                            padding: '16px 18px',
                                            background: 'transparent',
                                            border: 'none',
                                            cursor: 'pointer',
                                            textAlign: 'left',
                                            color: 'inherit',
                                        }}
                                    >
                                        <div
                                            style={{
                                                width: 44,
                                                height: 44,
                                                borderRadius: 8,
                                                display: 'flex',
                                                alignItems: 'center',
                                                justifyContent: 'center',
                                                background: accent.iconBg,
                                                flexShrink: 0,
                                                border: `1px solid ${accent.riskColor}33`,
                                            }}
                                        >
                                            <Icon size={22} color={accent.riskColor} />
                                        </div>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
                                                <span style={{ fontWeight: 700, fontSize: 15 }}>{type}</span>
                                                <span
                                                    style={{
                                                        fontSize: 11,
                                                        fontWeight: 800,
                                                        padding: '3px 10px',
                                                        borderRadius: 999,
                                                        background: accent.tagBg,
                                                        color: accent.tagColor,
                                                    }}
                                                >
                                                    {severity}
                                                </span>
                                                {badges && badges.length > 0 ? badges.map(b => (
                                                    <span
                                                        key={`${_i}-${b}`}
                                                        style={{
                                                            fontSize: 10,
                                                            fontWeight: 700,
                                                            letterSpacing: '0.02em',
                                                            textTransform: 'uppercase',
                                                            padding: '3px 8px',
                                                            borderRadius: 999,
                                                            border: '1px solid rgba(10,132,255,0.35)',
                                                            background: 'rgba(10,132,255,0.14)',
                                                            color: '#7db7ff',
                                                        }}
                                                    >
                                                        {b}
                                                    </span>
                                                )) : null}
                                            </div>
                                            <div style={{ fontSize: 13, color: 'var(--text-secondary)', fontFamily: 'ui-monospace, monospace' }}>
                                                {file}:{line}
                                                <span style={{ color: 'var(--text-tertiary)', margin: '0 8px' }}>·</span>
                                                <span style={{ color: 'var(--text-secondary)' }}>{category}</span>
                                            </div>
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                                            <div style={{ textAlign: 'right' }}>
                                                <span style={{ fontSize: 18, fontWeight: 900, color: accent.riskColor }}>{risk}</span>
                                                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', marginLeft: 4 }}>RISK</span>
                                            </div>
                                            {open ? <ChevronUp size={18} color="var(--text-secondary)" /> : <ChevronDown size={18} color="var(--text-secondary)" />}
                                        </div>
                                    </button>
                                    {open && (
                                        <div
                                            style={{
                                                padding: '0 18px 16px 78px',
                                                fontSize: 12,
                                                color: 'var(--text-secondary)',
                                                fontFamily: 'ui-monospace, monospace',
                                                lineHeight: 1.6,
                                                borderTop: '1px solid rgba(255,255,255,0.06)',
                                                paddingTop: 12,
                                            }}
                                        >
                                            {evidence?.trim() || '—'}
                                        </div>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                )}
            </main>
        </div>
    )
}
