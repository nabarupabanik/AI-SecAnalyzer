import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Search, ChevronDown } from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'
import { deriveCategory, deriveRiskScore, severityStyle } from '../lib/vulnDisplay'

interface Vuln {
    file: string
    line: number
    type: string
    severity: string
    code: string
    analyzer?: string
    confidence?: string
}

interface ScanPayload {
    id: number
    project_path: string
    vulnerabilities: Vuln[]
}

const SEVERITY_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low'] as const
type SevFilter = (typeof SEVERITY_FILTERS)[number]
const ENGINE_FILTERS = ['All', 'python_ast', 'semgrep', 'codeql', 'binary_static'] as const
type EngineFilter = (typeof ENGINE_FILTERS)[number]

const PAGE_SIZE = 10
const MAX_PAGE_BUTTONS = 10

export default function VulnerabilitiesPage() {
    const { scanId } = useParams<{ scanId: string }>()
    const navigate = useNavigate()
    const [scan, setScan] = useState<ScanPayload | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [loading, setLoading] = useState(true)
    const [query, setQuery] = useState('')
    const [severityFilter, setSeverityFilter] = useState<SevFilter>('All')
    const [engineFilter, setEngineFilter] = useState<EngineFilter>('All')
    const [filterOpen, setFilterOpen] = useState(false)
    const [page, setPage] = useState(1)

    useEffect(() => {
        setPage(1)
    }, [query, severityFilter, engineFilter])

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
        if (!scan?.vulnerabilities) return []
        const q = query.trim().toLowerCase()
        return scan.vulnerabilities
            .map((v, i) => ({
                ...v,
                _i: i,
                category: deriveCategory(v.type),
                risk: deriveRiskScore(v.severity, v.type, v.file, v.line),
            }))
            .filter(v => {
                if (severityFilter !== 'All' && v.severity !== severityFilter) return false
                const analyzer = (v.analyzer || '').trim().toLowerCase()
                if (engineFilter !== 'All' && analyzer !== engineFilter.toLowerCase()) return false
                if (!q) return true
                const hay = `${v.type} ${v.file} ${v.severity} ${v.category} ${v.line} ${v.analyzer || ''} ${v.confidence || ''}`.toLowerCase()
                return hay.includes(q)
            })
    }, [scan, query, severityFilter, engineFilter])

    const totalPages = useMemo(() => Math.max(1, Math.ceil(rows.length / PAGE_SIZE)), [rows.length])

    useEffect(() => {
        setPage(p => Math.min(p, totalPages))
    }, [totalPages])

    const currentPage = Math.min(Math.max(1, page), totalPages)
    const pageRows = useMemo(
        () => rows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
        [rows, currentPage],
    )

    const pageNumberButtons = useMemo(() => {
        if (totalPages <= MAX_PAGE_BUTTONS) {
            return Array.from({ length: totalPages }, (_, i) => i + 1)
        }
        let start = Math.max(1, currentPage - Math.floor(MAX_PAGE_BUTTONS / 2))
        if (start + MAX_PAGE_BUTTONS - 1 > totalPages) {
            start = totalPages - MAX_PAGE_BUTTONS + 1
        }
        return Array.from({ length: MAX_PAGE_BUTTONS }, (_, i) => start + i)
    }, [totalPages, currentPage])

    const uniqueFiles = useMemo(() => {
        if (!scan?.vulnerabilities?.length) return 0
        return new Set(scan.vulnerabilities.map(v => v.file)).size
    }, [scan])

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading vulnerabilities…
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
            <DashboardSidebar scanId={scanId} active="vulnerabilities" />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px' }}>
                <header style={{ marginBottom: 24 }}>
                    <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Vulnerabilities</h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                        {scan.vulnerabilities.length} issue{scan.vulnerabilities.length === 1 ? '' : 's'} detected across {uniqueFiles} file{uniqueFiles === 1 ? '' : 's'}
                        {rows.length !== scan.vulnerabilities.length && (
                            <> · {rows.length} match current filters</>
                        )}
                        {rows.length > 0 && totalPages > 1 && (
                            <>
                                {' '}
                                · Page {currentPage} of {totalPages} ({PAGE_SIZE} per page)
                            </>
                        )}
                    </p>
                </header>

                <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
                    <div style={{
                        flex: 1, minWidth: 240, display: 'flex', alignItems: 'center', gap: 10,
                        padding: '12px 16px', borderRadius: 12,
                        background: 'rgba(30,30,36,0.95)', border: '1px solid rgba(255,255,255,0.08)',
                    }}>
                        <Search size={18} color="var(--text-tertiary)" />
                        <input
                            type="search"
                            placeholder="Search vulnerabilities..."
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            style={{
                                flex: 1, background: 'transparent', border: 'none', outline: 'none',
                                color: '#F5F5F7', fontSize: 14,
                            }}
                        />
                    </div>

                    <div style={{ position: 'relative' }}>
                        <button
                            type="button"
                            onClick={() => setFilterOpen(o => !o)}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                padding: '12px 18px', borderRadius: 12, cursor: 'pointer',
                                background: 'rgba(30,30,36,0.95)', border: '1px solid rgba(255,255,255,0.12)',
                                color: '#F5F5F7', fontSize: 14, fontWeight: 600, minWidth: 120,
                            }}
                        >
                            {severityFilter} <ChevronDown size={16} color="var(--text-secondary)" />
                        </button>
                        {filterOpen && (
                            <>
                                <div
                                    role="presentation"
                                    style={{ position: 'fixed', inset: 0, zIndex: 40 }}
                                    onClick={() => setFilterOpen(false)}
                                />
                                <div style={{
                                    position: 'absolute', right: 0, top: 'calc(100% + 6px)', zIndex: 50,
                                    minWidth: 160, padding: 6, borderRadius: 10,
                                    background: 'rgba(35,35,42,0.98)', border: '1px solid rgba(255,255,255,0.1)',
                                    boxShadow: '0 12px 40px rgba(0,0,0,0.45)',
                                }}>
                                    {SEVERITY_FILTERS.map(s => (
                                        <button
                                            key={s}
                                            type="button"
                                            onClick={() => { setSeverityFilter(s); setFilterOpen(false) }}
                                            style={{
                                                display: 'block', width: '100%', textAlign: 'left',
                                                padding: '10px 14px', borderRadius: 8, border: 'none', cursor: 'pointer',
                                                background: s === severityFilter ? 'rgba(10,132,255,0.2)' : 'transparent',
                                                color: '#F5F5F7', fontSize: 14,
                                            }}
                                        >
                                            {s}
                                        </button>
                                    ))}
                                </div>
                            </>
                        )}
                    </div>
                    <div>
                        <select
                            value={engineFilter}
                            onChange={e => setEngineFilter(e.target.value as EngineFilter)}
                            style={{
                                padding: '12px 12px',
                                borderRadius: 12,
                                background: 'rgba(30,30,36,0.95)',
                                border: '1px solid rgba(255,255,255,0.12)',
                                color: '#F5F5F7',
                                fontSize: 14,
                                fontWeight: 600,
                            }}
                        >
                            {ENGINE_FILTERS.map(e => (
                                <option key={e} value={e}>
                                    {e === 'All' ? 'All engines' : e}
                                </option>
                            ))}
                        </select>
                    </div>
                </div>

                <div className="glass-card" style={{ overflow: 'hidden', background: 'rgba(30,30,36,0.85)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', textAlign: 'left' }}>
                                {(['TYPE', 'SEVERITY', 'ENGINE', 'CONF', 'FILE', 'LINE', 'CATEGORY', 'RISK'] as const).map(col => (
                                    <th
                                        key={col}
                                        style={{
                                            padding: '14px 16px',
                                            fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
                                            color: 'var(--text-tertiary)', textTransform: 'uppercase',
                                        }}
                                    >
                                        {col}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {rows.length === 0 ? (
                                <tr>
                                    <td colSpan={8} style={{ padding: 32, textAlign: 'center', color: 'var(--text-secondary)' }}>
                                        No vulnerabilities match your filters.
                                    </td>
                                </tr>
                            ) : (
                                pageRows.map(v => {
                                    const st = severityStyle(v.severity)
                                    return (
                                        <tr key={`${v.file}-${v.line}-${v._i}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                            <td style={{ padding: '14px 16px', fontWeight: 600 }}>{v.type}</td>
                                            <td style={{ padding: '14px 16px' }}>
                                                <span style={{
                                                    display: 'inline-block', padding: '4px 10px', borderRadius: 999,
                                                    fontSize: 12, fontWeight: 700,
                                                    background: st.bg, border: `1px solid ${st.border}`, color: st.color,
                                                }}>
                                                    {v.severity}
                                                </span>
                                            </td>
                                            <td style={{ padding: '14px 16px' }}>
                                                <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 999, background: 'rgba(10,132,255,0.18)', color: '#7db7ff', border: '1px solid rgba(10,132,255,0.32)' }}>
                                                    {v.analyzer || 'python_ast'}
                                                </span>
                                            </td>
                                            <td style={{ padding: '14px 16px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                                                {v.confidence || '—'}
                                            </td>
                                            <td style={{ padding: '14px 16px', fontFamily: 'ui-monospace, monospace', fontSize: 12, color: 'rgba(245,245,247,0.9)' }}>
                                                {v.file}
                                            </td>
                                            <td style={{ padding: '14px 16px', fontFamily: 'ui-monospace, monospace', color: 'var(--text-secondary)' }}>
                                                :{v.line}
                                            </td>
                                            <td style={{ padding: '14px 16px', color: 'rgba(245,245,247,0.85)' }}>{v.category}</td>
                                            <td style={{ padding: '14px 16px', fontWeight: 800, color: st.riskColor }}>{v.risk}</td>
                                        </tr>
                                    )
                                })
                            )}
                        </tbody>
                    </table>
                </div>

                {rows.length > PAGE_SIZE && (
                    <nav
                        aria-label="Vulnerability pages"
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 10,
                            marginTop: 24,
                            flexWrap: 'wrap',
                            fontSize: 14,
                        }}
                    >
                        <button
                            type="button"
                            className="btn-ghost"
                            disabled={currentPage <= 1}
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            style={{ opacity: currentPage <= 1 ? 0.4 : 1, cursor: currentPage <= 1 ? 'default' : 'pointer' }}
                        >
                            Previous
                        </button>
                        {pageNumberButtons.map(num => (
                            <button
                                key={num}
                                type="button"
                                onClick={() => setPage(num)}
                                style={{
                                    minWidth: 32,
                                    padding: '6px 10px',
                                    borderRadius: 8,
                                    border: 'none',
                                    cursor: 'pointer',
                                    fontWeight: 700,
                                    fontSize: 14,
                                    background: 'transparent',
                                    color: num === currentPage ? '#e8b87a' : '#64b5ff',
                                    textDecoration: num === currentPage ? 'none' : 'underline',
                                    textUnderlineOffset: 3,
                                }}
                            >
                                {num}
                            </button>
                        ))}
                        <button
                            type="button"
                            className="btn-ghost"
                            disabled={currentPage >= totalPages}
                            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                            style={{ opacity: currentPage >= totalPages ? 0.4 : 1, cursor: currentPage >= totalPages ? 'default' : 'pointer', color: '#64b5ff', fontWeight: 600 }}
                        >
                            Next
                        </button>
                    </nav>
                )}
            </main>
        </div>
    )
}
