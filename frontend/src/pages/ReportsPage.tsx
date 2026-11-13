import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
    Info, AlertTriangle, Activity, Bug, Fingerprint, Star,
    FileDown, Download, FileText, FileCode, ShieldCheck,
} from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'
import {
    type ScanReportPayload,
    formatReportId,
    fmtLongDate,
    countVulnSeverity,
    combinedDimensionScores,
    buildExecutiveSummary,
    buildVulnSection,
    buildProcessSection,
    buildMaliciousSection,
    buildTamperSection,
    buildFinalSection,
    recommendedActions,
    buildReportHtml,
} from '../lib/reportSummary'

const SECTION_ICONS = [Info, AlertTriangle, Activity, Bug, Fingerprint, Star]
const SECTION_TITLES = [
    'Executive Summary',
    'Vulnerabilities Summary',
    'Process Behavior Report',
    'Malicious Pattern Summary',
    'Tamperability Summary',
    'Final Combined Security Score',
]

function derivePathBadges(p: { sink: string; category?: string; sanitized?: boolean; confidence?: string; evidence?: string }): string[] {
    const s = `${p.sink || ''} ${p.evidence || ''}`.toLowerCase()
    const out: string[] = []
    if (s.includes('cross_file=true') || s.includes('cross-file') || s.includes('cross_file')) out.push('cross-file')
    if (s.includes('interprocedural') || s.includes('wrapper=')) out.push('interprocedural')
    if (s.includes('correlation') || s.includes('behavior_chain_score=')) out.push('correlated')
    if (p.sanitized) out.push('sanitized')
    if ((p.category || '').toLowerCase() === 'template') out.push('template')
    else if ((p.category || '').toLowerCase() === 'system') out.push('system')
    if ((p.confidence || '').toLowerCase() === 'high') out.push('high-confidence')
    return Array.from(new Set(out))
}

export default function ReportsPage() {
    const { scanId } = useParams<{ scanId: string }>()
    const navigate = useNavigate()
    const [scan, setScan] = useState<ScanReportPayload | null>(null)
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
                if (!cancelled) setScan(data.scan as ScanReportPayload)
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

    const dims = useMemo(() => (scan ? combinedDimensionScores(scan) : null), [scan])
    const sev = useMemo(() => (scan ? countVulnSeverity(scan.vulnerabilities) : null), [scan])
    const reportId = useMemo(() => (scan ? formatReportId(scan.id, scan.created_at) : ''), [scan])

    const bodies = useMemo(() => {
        if (!scan || !dims) return []
        return [
            buildExecutiveSummary(scan),
            buildVulnSection(scan),
            buildProcessSection(scan),
            buildMaliciousSection(scan),
            buildTamperSection(scan),
            buildFinalSection(dims) + ' ' + recommendedActions(scan).map((a, i) => `(${i + 1}) ${a}`).join(' '),
        ]
    }, [scan, dims])

    const topRiskyPaths = useMemo(() => {
        if (!scan?.taint_paths?.length) return []
        const sevRank = (s: string) => ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[s] || 0)
        const confRank = (c?: string) => ({ High: 3, Medium: 2, Low: 1 }[(c || 'Medium') as 'High' | 'Medium' | 'Low'] || 0)
        return [...scan.taint_paths]
            .sort((a, b) => {
                const s = sevRank(b.severity) - sevRank(a.severity)
                if (s) return s
                const c = confRank(b.confidence) - confRank(a.confidence)
                if (c) return c
                return (b.count || 1) - (a.count || 1)
            })
            .slice(0, 5)
    }, [scan])

    const exportJsonHref = scan ? `/api/scans/${scan.id}/export` : '#'
    const exportSarifHref = scan ? `/api/scans/${scan.id}/sarif` : '#'

    const downloadHtml = useCallback(() => {
        if (!scan || !dims) return
        const html = buildReportHtml(scan, dims)
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `scan_report_${scan.id}.html`
        a.click()
        URL.revokeObjectURL(url)
    }, [scan, dims])

    const printPdf = useCallback(() => {
        window.print()
    }, [])

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading report…
            </div>
        )
    }

    if (error || !scan || !scanId || !dims || !sev) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: 40 }}>
                <p style={{ color: '#FF453A', marginBottom: 16 }}>{error || 'Scan not found.'}</p>
                <button className="btn-ghost" onClick={() => navigate('/')}>Back to Home</button>
            </div>
        )
    }

    const rs = scan.risk_score ?? 0
    const pathDisplay = scan.project_path.replace(/\\/g, '/')

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: '#F5F5F7' }}>
            <div className="no-print">
                <DashboardSidebar scanId={scanId} active="reports" />
            </div>

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px', minWidth: 0 }} id="report-print-area">
                <div className="no-print" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap', marginBottom: 28 }}>
                    <div>
                        <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Security Report</h1>
                        <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                            Application Security & Risk Analyzer · {fmtLongDate(scan.created_at)}
                        </p>
                    </div>
                    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                        <button
                            type="button"
                            className="btn-ghost"
                            onClick={printPdf}
                            style={{
                                borderRadius: 10,
                                border: '1px solid rgba(255,69,58,0.45)',
                                color: '#FF6B65',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 8,
                                padding: '10px 14px',
                            }}
                        >
                            <FileText size={18} /> Export PDF
                        </button>
                        <button
                            type="button"
                            className="btn-ghost"
                            onClick={downloadHtml}
                            style={{
                                borderRadius: 10,
                                border: '1px solid rgba(255,159,10,0.45)',
                                color: '#FF9F0A',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 8,
                                padding: '10px 14px',
                            }}
                        >
                            <FileCode size={18} /> Export HTML
                        </button>
                        <a
                            className="btn-primary"
                            href={exportJsonHref}
                            download
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 8,
                                padding: '10px 14px',
                                borderRadius: 10,
                                border: '1px solid rgba(10,132,255,0.35)',
                                textDecoration: 'none',
                            }}
                        >
                            <Download size={18} /> Download JSON
                        </a>
                        <a
                            className="btn-ghost"
                            href={exportSarifHref}
                            download
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 8,
                                padding: '10px 14px',
                                borderRadius: 10,
                                border: '1px solid rgba(48,209,88,0.35)',
                                color: '#30D158',
                                textDecoration: 'none',
                            }}
                        >
                            <ShieldCheck size={18} /> Export SARIF
                        </a>
                    </div>
                </div>

                {/* Summary banner */}
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 24,
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '20px 22px',
                        borderRadius: 14,
                        background: 'rgba(10,40,80,0.35)',
                        border: '1px solid rgba(10,132,255,0.2)',
                        marginBottom: 24,
                    }}
                >
                    <div style={{ minWidth: 200 }}>
                        <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '0.1em', color: 'var(--text-tertiary)', marginBottom: 6 }}>REPORT ID</div>
                        <div style={{ fontSize: 16, fontWeight: 800, marginBottom: 10 }}>{reportId}</div>
                        <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                            <strong style={{ color: 'var(--text-secondary)' }}>Project:</strong> {pathDisplay}
                        </div>
                        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                            <strong style={{ color: 'var(--text-secondary)' }}>Scan date:</strong> {fmtLongDate(scan.created_at)}
                        </div>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 20, alignItems: 'flex-end' }}>
                        <MetricBlock label="Risk Score" value={`${rs}/100`} color="#f5f5f7" />
                        <MetricBlock label="Critical" value={String(sev.Critical)} color="#FF453A" />
                        <MetricBlock label="High" value={String(sev.High)} color="#FF9F0A" />
                        <MetricBlock label="Medium" value={String(sev.Medium)} color="#FFD60A" />
                        <MetricBlock label="Low" value={String(sev.Low)} color="#0A84FF" />
                        <MetricBlock label="Files" value={String(scan.file_count)} color="#f5f5f7" />
                    </div>
                </div>

                {/* Section cards */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {SECTION_TITLES.map((title, i) => {
                        const Icon = SECTION_ICONS[i]
                        const body = bodies[i] || ''
                        return (
                            <div
                                key={title}
                                style={{
                                    borderRadius: 12,
                                    background: '#161b22',
                                    border: '1px solid rgba(255,255,255,0.08)',
                                    padding: '18px 20px',
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Icon size={20} color={i === 0 ? '#0A84FF' : i === 1 ? '#FF453A' : i === 2 ? '#FF9F0A' : i === 3 ? '#FF453A' : i === 4 ? '#FF9F0A' : '#30D158'} />
                                        <span style={{ fontWeight: 700, fontSize: 16 }}>{title}</span>
                                    </div>
                                    <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)' }}>
                                        Section {i + 1} of 6
                                    </span>
                                </div>
                                <p style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--text-secondary)' }}>{body}</p>
                            </div>
                        )
                    })}
                </div>

                {/* Top risky paths */}
                <div
                    style={{
                        marginTop: 16,
                        borderRadius: 12,
                        background: '#161b22',
                        border: '1px solid rgba(255,255,255,0.08)',
                        padding: '18px 20px',
                    }}
                >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                        <AlertTriangle size={20} color="#FF9F0A" />
                        <span style={{ fontWeight: 700, fontSize: 16 }}>Top Risky Paths</span>
                    </div>
                    {topRiskyPaths.length === 0 ? (
                        <p style={{ fontSize: 14, lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                            No grouped source-to-sink taint paths were available for this scan.
                        </p>
                    ) : (
                        <div style={{ display: 'grid', gap: 8 }}>
                            {topRiskyPaths.map((p, i) => (
                                <div key={`${p.file}-${p.line}-${p.sink}-${i}`} style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                                    <span style={{ color: '#FF9F0A', fontWeight: 700 }}>{p.severity}</span>
                                    {' - '}
                                    <span style={{ fontFamily: 'ui-monospace, monospace' }}>{p.source} {'->'} {p.sink}</span>
                                    <span style={{ marginLeft: 8, display: 'inline-flex', gap: 6, flexWrap: 'wrap', verticalAlign: 'middle' }}>
                                        {derivePathBadges(p).map(b => (
                                            <span
                                                key={`${p.file}-${p.line}-${b}`}
                                                style={{
                                                    fontSize: 10,
                                                    fontWeight: 700,
                                                    letterSpacing: '0.02em',
                                                    textTransform: 'uppercase',
                                                    padding: '2px 7px',
                                                    borderRadius: 999,
                                                    border: '1px solid rgba(10,132,255,0.35)',
                                                    background: 'rgba(10,132,255,0.14)',
                                                    color: '#7db7ff',
                                                }}
                                            >
                                                {b}
                                            </span>
                                        ))}
                                    </span>
                                    {p.confidence ? (
                                        <span style={{ marginLeft: 8, color: 'var(--text-secondary)' }}>
                                            [{p.confidence} confidence]
                                        </span>
                                    ) : null}
                                    {p.count && p.count > 1 ? (
                                        <span style={{ marginLeft: 8, color: 'var(--text-secondary)' }}>
                                            ({p.count} occurrences)
                                        </span>
                                    ) : null}
                                    {' at '}
                                    <span>{p.file.replace(/\\/g, '/')}:{p.line}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Export footer */}
                <div
                    className="no-print"
                    style={{
                        marginTop: 28,
                        padding: 22,
                        borderRadius: 14,
                        background: '#161b22',
                        border: '1px solid rgba(255,255,255,0.08)',
                    }}
                >
                    <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 6 }}>Ready to export this report?</div>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 16 }}>
                        Download in your preferred format for stakeholder distribution. JSON export includes the full scan payload from the database.
                    </p>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                        <button type="button" className="btn-primary" onClick={printPdf} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                            <FileDown size={18} /> Export PDF
                        </button>
                        <a className="btn-ghost" href={exportJsonHref} download style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                            <Download size={18} /> Download JSON
                        </a>
                        <a className="btn-ghost" href={exportSarifHref} download style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                            <ShieldCheck size={18} /> Export SARIF
                        </a>
                    </div>
                </div>
            </main>
        </div>
    )
}

function MetricBlock({ label, value, color }: { label: string; value: string; color: string }) {
    return (
        <div style={{ textAlign: 'center', minWidth: 56 }}>
            <div style={{ fontSize: 22, fontWeight: 900, color }}>{value}</div>
            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-tertiary)', marginTop: 4 }}>{label}</div>
        </div>
    )
}
