import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Server, Loader2, CheckCircle2, XCircle, ExternalLink } from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'

interface TelemetrySummary {
    status: string
    total_samples: number
    avg_duration_ms: number
    semgrep_cache_hits_recorded: number
    codeql_runs_recorded: number
    codeql_findings_recorded: number
    recent: Array<{
        scan_id: number
        duration_ms: number
        vulnerability_count: number
        file_count: number
        semgrep_cache_hit: boolean
        codeql_enabled: boolean
        codeql_finding_count: number
        error: string
        created_at: string | null
    }>
}

interface ScanListResponse {
    status: string
    scans: Array<{ id: number }>
}

const ASYNC_SCAN_MODES = [
    { id: 'basic', label: 'Basic Scan' },
    { id: 'behavioral', label: 'Behavioral Deep Scan' },
    { id: 'full', label: 'Full Intelligence Scan' },
] as const

interface JobPayload {
    id: number
    status: string
    project_path: string
    scan_mode: string
    load_content: boolean
    incremental: boolean
    codeql_enabled: boolean
    result_scan_id: number | null
    error_message: string
    created_at: string | null
    started_at: string | null
    completed_at: string | null
}

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
    return (
        <button type="button" role="switch" aria-checked={on} onClick={onToggle} className={`toggle-track ${on ? 'on' : ''}`}>
            <div className="toggle-thumb" />
        </button>
    )
}

export default function TelemetryPage() {
    const [sideScanId, setSideScanId] = useState<string>('0')
    const [summary, setSummary] = useState<TelemetrySummary | null>(null)
    const [summaryError, setSummaryError] = useState<string | null>(null)
    const [summaryLoading, setSummaryLoading] = useState(true)

    const [pathInput, setPathInput] = useState('')
    const [asyncScanMode, setAsyncScanMode] = useState<string>('behavioral')
    const [asyncIncremental, setAsyncIncremental] = useState(false)
    const [asyncCodeql, setAsyncCodeql] = useState(false)
    const [pathHint, setPathHint] = useState<string | null>(null)
    const [queueBusy, setQueueBusy] = useState(false)
    const [queueError, setQueueError] = useState<string | null>(null)
    const [activeJobId, setActiveJobId] = useState<number | null>(null)
    const [job, setJob] = useState<JobPayload | null>(null)

    const loadSummary = useCallback(async () => {
        setSummaryError(null)
        try {
            const res = await fetch('/api/telemetry/summary?limit=50')
            const json = (await res.json()) as TelemetrySummary
            if (!res.ok || json.status !== 'success') {
                setSummaryError('Could not load telemetry.')
                return
            }
            setSummary(json)
        } catch {
            setSummaryError('Cannot reach API server.')
        } finally {
            setSummaryLoading(false)
        }
    }, [])

    useEffect(() => {
        let cancelled = false
        ;(async () => {
            try {
                const res = await fetch('/api/scans?limit=1')
                const json = (await res.json()) as ScanListResponse
                if (!cancelled && json.status === 'success' && json.scans?.[0]?.id != null) {
                    setSideScanId(String(json.scans[0].id))
                }
            } catch {
                /* sidebar fallback */
            }
        })()
        return () => {
            cancelled = true
        }
    }, [])

    useEffect(() => {
        void loadSummary()
    }, [loadSummary])

    useEffect(() => {
        if (activeJobId == null) return
        let cancelled = false
        let interval: number

        async function poll() {
            try {
                const res = await fetch(`/api/jobs/${activeJobId}`)
                const json = await res.json()
                if (cancelled || json.status !== 'success') return
                setJob(json.job as JobPayload)
                const st = (json.job as JobPayload).status
                if (st === 'completed' || st === 'failed') {
                    window.clearInterval(interval)
                    void loadSummary()
                }
            } catch {
                /* ignore transient */
            }
        }

        void poll()
        interval = window.setInterval(poll, 1200)
        return () => {
            cancelled = true
            window.clearInterval(interval)
        }
    }, [activeJobId, loadSummary])

    async function validatePath() {
        setPathHint(null)
        const p = pathInput.trim()
        if (!p) {
            setPathHint('Enter a directory path on the machine running the API.')
            return
        }
        try {
            const res = await fetch('/api/validate-path', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: p }),
            })
            const json = await res.json()
            if (json.valid) setPathHint(`OK — ${json.resolved as string}`)
            else setPathHint(json.message as string)
        } catch {
            setPathHint('Request failed.')
        }
    }

    async function queueScan() {
        setQueueError(null)
        const p = pathInput.trim()
        if (!p) {
            setQueueError('Project path is required.')
            return
        }
        setQueueBusy(true)
        try {
            const res = await fetch('/api/scan-async', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    path: p,
                    scan_mode: asyncScanMode,
                    load_content: true,
                    incremental: asyncIncremental,
                    codeql_enabled: asyncCodeql,
                }),
            })
            const json = await res.json()
            if (!res.ok || json.status !== 'success' || typeof json.job_id !== 'number') {
                setQueueError((json.error as string) || 'Failed to queue job.')
                return
            }
            setActiveJobId(json.job_id as number)
            setJob(null)
        } catch {
            setQueueError('Cannot reach API server.')
        } finally {
            setQueueBusy(false)
        }
    }

    const cacheRate =
        summary && summary.total_samples > 0
            ? Math.round((summary.semgrep_cache_hits_recorded / summary.total_samples) * 1000) / 10
            : null

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: '#F5F5F7' }}>
            <DashboardSidebar scanId={sideScanId} active="telemetry" noScanContext={sideScanId === '0'} />

            <main style={{ flex: 1, overflow: 'auto', padding: '32px 40px 48px', minWidth: 0 }}>
                <div style={{ marginBottom: 28 }}>
                    <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 8 }}>Telemetry &amp; Queue</h1>
                    <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                        Scan duration samples, Semgrep cache hits, and background path scans (Phase 4).
                    </p>
                </div>

                <div
                    className="glass-card"
                    style={{
                        padding: 22,
                        marginBottom: 22,
                        background: '#161b22',
                        border: '1px solid rgba(255,255,255,0.08)',
                        borderRadius: 12,
                    }}
                >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                        <Server size={20} color="#0A84FF" />
                        <div style={{ fontSize: 16, fontWeight: 700 }}>Queue server-path scan</div>
                    </div>
                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 16 }}>
                        The API must reach this folder on disk (same host as <code style={{ color: 'rgba(10,132,255,0.9)' }}>api_server.py</code>).
                        Incremental Semgrep reuse works best when the resolved path stays the same between runs.
                    </p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end', marginBottom: 14 }}>
                        <div style={{ minWidth: 200 }}>
                            <div className="section-label" style={{ marginBottom: 8 }}>Scan mode</div>
                            <select
                                value={asyncScanMode}
                                onChange={e => setAsyncScanMode(e.target.value)}
                                style={{
                                    width: '100%',
                                    padding: '11px 14px',
                                    borderRadius: 10,
                                    border: '1px solid rgba(255,255,255,0.12)',
                                    background: 'rgba(0,0,0,0.35)',
                                    color: '#f5f5f7',
                                    fontSize: 14,
                                }}
                            >
                                {ASYNC_SCAN_MODES.map(m => (
                                    <option key={m.id} value={m.id}>
                                        {m.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div style={{ flex: '1 1 280px', minWidth: 0 }}>
                            <div className="section-label" style={{ marginBottom: 8 }}>Project directory</div>
                            <input
                                type="text"
                                value={pathInput}
                                onChange={e => setPathInput(e.target.value)}
                                placeholder="e.g. C:\dev\myapp or /home/user/myapp"
                                style={{
                                    width: '100%',
                                    padding: '11px 14px',
                                    borderRadius: 10,
                                    border: '1px solid rgba(255,255,255,0.12)',
                                    background: 'rgba(0,0,0,0.35)',
                                    color: '#f5f5f7',
                                    fontSize: 14,
                                }}
                            />
                        </div>
                        <button type="button" className="btn-ghost" onClick={() => void validatePath()}>
                            Validate path
                        </button>
                        <button
                            type="button"
                            className="btn-primary"
                            onClick={() => void queueScan()}
                            disabled={queueBusy}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}
                        >
                            {queueBusy ? <Loader2 size={18} className="spin" /> : null}
                            Queue scan
                        </button>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                        <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Incremental Semgrep</span>
                        <Toggle on={asyncIncremental} onToggle={() => setAsyncIncremental(p => !p)} />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                        <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Deep scan (CodeQL on)</span>
                        <Toggle on={asyncCodeql} onToggle={() => setAsyncCodeql(p => !p)} />
                    </div>
                    {pathHint && (
                        <div style={{ fontSize: 13, color: pathHint.startsWith('OK') ? '#30D158' : '#FF9F0A', marginBottom: 10 }}>{pathHint}</div>
                    )}
                    {queueError && <div style={{ fontSize: 13, color: '#FF453A', marginBottom: 10 }}>{queueError}</div>}
                    {activeJobId != null && (
                        <div
                            style={{
                                marginTop: 8,
                                padding: '14px 16px',
                                borderRadius: 10,
                                background: 'rgba(0,0,0,0.3)',
                                border: '1px solid rgba(255,255,255,0.06)',
                            }}
                        >
                            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-tertiary)', marginBottom: 8 }}>JOB #{activeJobId}</div>
                            {!job ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-secondary)' }}>
                                    <Loader2 size={18} style={{ animation: 'spin 0.9s linear infinite' }} />
                                    Loading status…
                                </div>
                            ) : (
                                <>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                                        {job.status === 'completed' ? (
                                            <CheckCircle2 size={18} color="#30D158" />
                                        ) : job.status === 'failed' ? (
                                            <XCircle size={18} color="#FF453A" />
                                        ) : (
                                            <Loader2 size={18} style={{ animation: 'spin 0.9s linear infinite' }} />
                                        )}
                                        <span style={{ fontWeight: 700, textTransform: 'capitalize' }}>{job.status}</span>
                                        <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 6, background: 'rgba(245,245,247,0.08)', color: 'var(--text-secondary)' }}>
                                            {ASYNC_SCAN_MODES.find(m => m.id === job.scan_mode)?.label ?? job.scan_mode}
                                        </span>
                                        {job.incremental && (
                                            <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 6, background: 'rgba(10,132,255,0.2)', color: '#0A84FF' }}>
                                                incremental
                                            </span>
                                        )}
                                        {job.codeql_enabled && (
                                            <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 6, background: 'rgba(10,132,255,0.2)', color: '#7db7ff' }}>
                                                codeql
                                            </span>
                                        )}
                                    </div>
                                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all', marginBottom: 10 }}>{job.project_path}</div>
                                    {job.error_message ? (
                                        <div style={{ fontSize: 13, color: '#FF453A', marginBottom: 10 }}>{job.error_message}</div>
                                    ) : null}
                                    {job.status === 'completed' && job.result_scan_id != null ? (
                                        <Link
                                            to={`/dashboard/${job.result_scan_id}`}
                                            className="btn-primary"
                                            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, textDecoration: 'none', padding: '8px 14px', fontSize: 13 }}
                                        >
                                            Open scan <ExternalLink size={14} />
                                        </Link>
                                    ) : null}
                                </>
                            )}
                        </div>
                    )}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                    <h2 style={{ fontSize: 18, fontWeight: 700 }}>Telemetry summary</h2>
                    <button type="button" className="btn-ghost" onClick={() => void loadSummary()} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <RefreshCw size={16} /> Refresh
                    </button>
                </div>

                {summaryLoading ? (
                    <p style={{ color: 'var(--text-secondary)' }}>Loading…</p>
                ) : summaryError ? (
                    <p style={{ color: '#FF453A' }}>{summaryError}</p>
                ) : summary ? (
                    <>
                        <div
                            style={{
                                display: 'flex',
                                flexWrap: 'wrap',
                                gap: 24,
                                padding: '18px 22px',
                                borderRadius: 12,
                                background: '#161b22',
                                border: '1px solid rgba(255,255,255,0.08)',
                                marginBottom: 20,
                            }}
                        >
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>SAMPLES</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: '#0A84FF' }}>{summary.total_samples}</div>
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>AVG DURATION</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: '#2DD4BF' }}>{summary.avg_duration_ms.toFixed(0)} ms</div>
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>SEMGREP CACHE HITS</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: '#FF9F0A' }}>{summary.semgrep_cache_hits_recorded}</div>
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>HIT RATE</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--text-primary)' }}>{cacheRate != null ? `${cacheRate}%` : '—'}</div>
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>CODEQL RUNS</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: '#7db7ff' }}>{summary.codeql_runs_recorded}</div>
                            </div>
                            <div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>CODEQL FINDINGS</div>
                                <div style={{ fontSize: 26, fontWeight: 900, color: '#f5f5f7' }}>{summary.codeql_findings_recorded}</div>
                            </div>
                        </div>

                        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10, color: 'var(--text-secondary)' }}>Recent runs</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {summary.recent.length === 0 ? (
                                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-tertiary)', background: '#161b22', borderRadius: 12, border: '1px solid rgba(255,255,255,0.06)' }}>
                                    No telemetry rows yet. Complete a scan to populate metrics.
                                </div>
                            ) : (
                                summary.recent.map((row, idx) => (
                                    <div
                                        key={`${row.scan_id}-${row.created_at ?? ''}-${idx}`}
                                        style={{
                                            display: 'grid',
                                            gridTemplateColumns: 'minmax(0,1fr) auto auto auto',
                                            gap: 12,
                                            alignItems: 'center',
                                            padding: '12px 16px',
                                            borderRadius: 10,
                                            background: '#161b22',
                                            border: '1px solid rgba(255,255,255,0.06)',
                                            fontSize: 13,
                                        }}
                                    >
                                        <div>
                                            <Link to={`/dashboard/${row.scan_id}`} style={{ color: '#0A84FF', fontWeight: 700, textDecoration: 'none' }}>
                                                Scan #{row.scan_id}
                                            </Link>
                                            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>
                                                {row.created_at ? new Date(row.created_at).toLocaleString() : '—'}
                                            </div>
                                            {row.error ? <div style={{ fontSize: 11, color: '#FF453A', marginTop: 4 }}>{row.error}</div> : null}
                                        </div>
                                        <div style={{ textAlign: 'right', color: 'var(--text-secondary)' }}>{row.duration_ms.toFixed(0)} ms</div>
                                        <div style={{ textAlign: 'right', color: '#f5f5f7' }}>{row.file_count} files</div>
                                        <div style={{ textAlign: 'right' }}>
                                            <span
                                                style={{
                                                    fontSize: 11,
                                                    fontWeight: 700,
                                                    padding: '4px 8px',
                                                    borderRadius: 6,
                                                    background: row.semgrep_cache_hit ? 'rgba(48,209,88,0.15)' : 'rgba(245,245,247,0.08)',
                                                    color: row.semgrep_cache_hit ? '#30D158' : 'var(--text-secondary)',
                                                }}
                                            >
                                                {row.semgrep_cache_hit ? 'cache hit' : 'fresh'}
                                            </span>
                                            {row.codeql_enabled ? (
                                                <span style={{ marginLeft: 6, fontSize: 11, fontWeight: 700, padding: '4px 8px', borderRadius: 6, background: 'rgba(10,132,255,0.2)', color: '#7db7ff' }}>
                                                    codeql:{row.codeql_finding_count}
                                                </span>
                                            ) : null}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </>
                ) : null}

                <style>{`
                    @keyframes spin { to { transform: rotate(360deg); } }
                    .spin { animation: spin 0.9s linear infinite; }
                `}</style>
            </main>
        </div>
    )
}
