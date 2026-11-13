import { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
    ArrowLeft, FolderOpen, CheckCircle2, AlertCircle,
    Play, X, ChevronRight, Clock, Upload, Server,
} from 'lucide-react'

/* ── Language detection (client-side) ─────────────────────── */
const LANG_MAP: Record<string, string> = {
    '.py': 'Python', '.pyw': 'Python',
    '.js': 'JavaScript', '.mjs': 'JavaScript', '.jsx': 'JavaScript',
    '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.java': 'Java',
    '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.h': 'C/C++',
    '.c': 'C',
    '.json': 'JSON',
    '.yaml': 'YAML', '.yml': 'YAML',
    '.html': 'HTML', '.htm': 'HTML',
    '.css': 'CSS', '.scss': 'CSS',
    '.php': 'PHP', '.rb': 'Ruby', '.go': 'Go', '.rs': 'Rust',
    '.sh': 'Shell', '.bash': 'Shell',
    '.sql': 'SQL', '.xml': 'XML', '.toml': 'TOML',
    '.ini': 'Config', '.cfg': 'Config', '.env': 'Config',
}
function detectLangs(names: string[]): string[] {
    const seen = new Set<string>()
    for (const n of names) {
        const dot = n.lastIndexOf('.')
        if (dot !== -1) { const l = LANG_MAP[n.slice(dot).toLowerCase()]; if (l) seen.add(l) }
    }
    return Array.from(seen).sort()
}

/* ── FileSystem API helpers ────────────────────────────────── */
const SKIP = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv',
    'dist', 'build', '.next', '.cache', 'coverage', '.idea', '.vs'])

function readDirEntries(dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
    return new Promise(res => {
        const reader = dir.createReader()
        const all: FileSystemEntry[] = []
        function batch() {
            reader.readEntries(e => { if (!e.length) res(all); else { all.push(...e); batch() } }, () => res(all))
        }
        batch()
    })
}

async function collectFilesFromEntry(
    entry: FileSystemEntry,
    currentPath = '',
): Promise<{ file: File; path: string }[]> {
    const entryPath = currentPath ? `${currentPath}/${entry.name}` : entry.name
    if (entry.isFile) {
        return new Promise(res => {
            ; (entry as FileSystemFileEntry).file(f => res([{ file: f, path: entryPath }]), () => res([]))
        })
    }
    // Directory — skip heavy dirs (but not the root)
    if (currentPath !== '' && SKIP.has(entry.name)) return []
    const children = await readDirEntries(entry as FileSystemDirectoryEntry)
    const results = await Promise.all(children.map(c => collectFilesFromEntry(c, entryPath)))
    return results.flat()
}

/* ── Types ─────────────────────────────────────────────────── */
interface ScanModule { id: string; label: string; description: string; defaultOn: boolean }
interface ScanMode { id: string; label: string; description: string; time: string }
interface ApiResult {
    status: 'success' | 'error'
    scan_id?: number
    elapsed_ms?: number
    model?: {
        file_count: number
        languages_detected: string[]
        folder_structure: string[]
        language_breakdown: Record<string, number>
        total_size_bytes: number
        vulnerabilities?: unknown[]
        process_events?: unknown[]
        malicious_indicators?: unknown[]
        tamperability?: unknown[]
        overall_score?: number
        risk_level?: string
    }
    error?: string
}

interface AsyncJob {
    id: number
    status: 'queued' | 'running' | 'completed' | 'failed'
    result_scan_id: number | null
    error_message: string
    codeql_enabled?: boolean
}

const SCAN_MODES: ScanMode[] = [
    { id: 'basic', label: 'Basic Scan', description: 'Surface-level static analysis', time: '~2 min' },
    { id: 'behavioral', label: 'Behavioral Deep Scan', description: 'Process & data flow analysis', time: '~8 min' },
    {
        id: 'full',
        label: 'Full Intelligence Scan',
        description: 'All analysis modules + CodeQL; Semgrep already uses full community packs on every scan',
        time: '~25+ min',
    },
]

const MODULES: ScanModule[] = [
    { id: 'static', label: 'Static Vulnerability Detection', description: 'Identify known vulnerability patterns via AST parsing and code flow analysis.', defaultOn: true },
    { id: 'process', label: 'Process Flow & PID Analysis', description: 'Trace process creation, PID hijacking, and subprocess invocations.', defaultOn: true },
    { id: 'taint', label: 'Taint Tracking', description: 'Follow user-controlled input from source to sink across function boundaries.', defaultOn: false },
    { id: 'malicious', label: 'Malicious Behavior Detection', description: 'Detect reverse shells, C2 patterns, obfuscation, and exfiltration vectors.', defaultOn: true },
    { id: 'tamper', label: 'Tamperability Assessment', description: 'Identify writable paths, exposed configs, and runtime manipulation risks.', defaultOn: false },
    { id: 'ai', label: 'AI Explanation Engine', description: 'Generate natural-language explanations for each detected risk and finding.', defaultOn: true },
    { id: 'graph', label: 'Generate Behavior Graph', description: 'Build interactive call-graph and process-flow visualization for the codebase.', defaultOn: false },
]

const MODE_PRESETS: Record<string, { modules: Record<string, boolean>; incrementalSemgrep: boolean; deepCodeql: boolean }> = {
    basic: {
        modules: {
            static: true,
            process: false,
            taint: false,
            malicious: false,
            tamper: false,
            ai: false,
            graph: false,
        },
        incrementalSemgrep: true,
        deepCodeql: false,
    },
    behavioral: {
        modules: {
            static: true,
            process: true,
            taint: true,
            malicious: true,
            tamper: false,
            ai: false,
            graph: true,
        },
        incrementalSemgrep: true,
        deepCodeql: false,
    },
    full: {
        modules: {
            static: true,
            process: true,
            taint: true,
            malicious: true,
            tamper: true,
            ai: true,
            graph: true,
        },
        incrementalSemgrep: false,
        deepCodeql: true,
    },
}

function presetSummary(modeId: string): string {
    const preset = MODE_PRESETS[modeId]
    if (!preset) return 'Preset unavailable'
    const enabledModules = MODULES
        .filter(m => Boolean(preset.modules[m.id]))
        .map(m => m.label)
    const semgrepLabel = preset.incrementalSemgrep ? 'Incremental Semgrep: On' : 'Incremental Semgrep: Off'
    const codeqlLabel = preset.deepCodeql ? 'Deep CodeQL: On' : 'Deep CodeQL: Off'
    return [
        `Modules: ${enabledModules.length ? enabledModules.join(', ') : 'None'}`,
        semgrepLabel,
        codeqlLabel,
        'Semgrep: full community SAST packs (always on server-side)',
    ].join('\n')
}

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
    return (
        <button role="switch" aria-checked={on} onClick={onToggle} className={`toggle-track ${on ? 'on' : ''}`}>
            <div className="toggle-thumb" />
        </button>
    )
}

/* ── Main Page ─────────────────────────────────────────────── */
export default function ScanConfigPage() {
    const navigate = useNavigate()
    const fileInputRef = useRef<HTMLInputElement>(null)
    const terminalScrollRef = useRef<HTMLDivElement>(null)
    /** Server max % (SSE); display animates 1→target one integer at a time */
    const progressTargetRef = useRef(0)

    // Upload state
    const [folderName, setFolderName] = useState('')
    const [uploadFiles, setUploadFiles] = useState<{ file: File; path: string }[]>([])
    const [clientLangs, setClientLangs] = useState<string[]>([])
    const [isDragging, setIsDragging] = useState(false)
    const [isReading, setIsReading] = useState(false)
    const [isLoaded, setIsLoaded] = useState(false)
    const [loadError, setLoadError] = useState<string | null>(null)
    const [apiResult, setApiResult] = useState<ApiResult | null>(null)
    const [isScanning, setIsScanning] = useState(false)
    const [scanMethod, setScanMethod] = useState<'upload' | 'server'>('upload')
    const [serverPath, setServerPath] = useState('')
    const [pathHint, setPathHint] = useState<string | null>(null)
    const [activeJobId, setActiveJobId] = useState<number | null>(null)
    const [jobState, setJobState] = useState<AsyncJob | null>(null)
    const [isQueueing, setIsQueueing] = useState(false)

    // Scan UI (Sprint 2+ frontend experience)
    const [scanView, setScanView] = useState<'config' | 'scanning'>('config')
    /** Shown in UI — steps through every integer 1…100 toward server target */
    const [displayProgress, setDisplayProgress] = useState(0)
    /** Server sent `done`; we enable results only after displayProgress reaches 100 */
    const [pendingComplete, setPendingComplete] = useState(false)
    const [filesScanned, setFilesScanned] = useState(0)
    const [vulnCount, setVulnCount] = useState(0)
    const [processCount, setProcessCount] = useState(0)
    const [maliciousCount, setMaliciousCount] = useState(0)
    const [terminalLines, setTerminalLines] = useState<string[]>([])
    const [scanDone, setScanDone] = useState(false)

    // Config state
    const [selectedMode, setSelectedMode] = useState('behavioral')
    const [incrementalSemgrep, setIncrementalSemgrep] = useState(MODE_PRESETS.behavioral.incrementalSemgrep)
    const [deepCodeql, setDeepCodeql] = useState(MODE_PRESETS.behavioral.deepCodeql)
    const [modules, setModules] = useState<Record<string, boolean>>(
        { ...MODE_PRESETS.behavioral.modules }
    )
    const selectedModeLabel = SCAN_MODES.find(m => m.id === selectedMode)?.label || 'Behavioral Deep Scan'

    const totalClientFiles = uploadFiles.length

    /** Append raw log line (backend already includes [mm:ss.x] timestamps). */
    function pushRawLine(line: string) {
        setTerminalLines(prev => [...prev.slice(-400), line])
    }

    function handleSseEvent(event: string, data: string) {
        if (event === 'log') {
            pushRawLine(data)
            return
        }
        if (event === 'progress') {
            try {
                const p = JSON.parse(data) as any
                if (typeof p.percent === 'number') {
                    const v = Math.max(0, Math.min(100, Math.round(p.percent)))
                    progressTargetRef.current = Math.max(progressTargetRef.current, v)
                }
                if (typeof p.saved === 'number') setFilesScanned(p.saved)
                if (typeof p.total === 'number' && typeof p.saved === 'number') setFilesScanned(p.saved)
                if (typeof p.files === 'number') setFilesScanned(p.files)
                if (typeof p.file_count === 'number') setFilesScanned(p.file_count)
                if (typeof p.vulnerabilities === 'number') setVulnCount(p.vulnerabilities)
                if (typeof p.process_events === 'number') setProcessCount(p.process_events)
                if (typeof p.malicious_indicators === 'number') setMaliciousCount(p.malicious_indicators)
                if (typeof p.malicious === 'number') setMaliciousCount(p.malicious)
            } catch {
                // ignore
            }
            return
        }
        if (event === 'result') {
            try {
                const result = JSON.parse(data) as ApiResult
                setApiResult(result)
                if (result.status !== 'success') setLoadError(result.error || 'Scan failed.')
                if (result.status === 'success' && result.model) {
                    const m: any = result.model
                    setVulnCount(Array.isArray(m.vulnerabilities) ? m.vulnerabilities.length : 0)
                    setProcessCount(Array.isArray(m.process_events) ? m.process_events.length : 0)
                    setMaliciousCount(Array.isArray(m.malicious_indicators) ? m.malicious_indicators.length : 0)
                    setFilesScanned(totalClientFiles || (m.file_count ?? 0))
                }
            } catch {
                // ignore
            }
            return
        }
        if (event === 'error') {
            setLoadError(data || 'Scan failed.')
            pushRawLine(`[ALERT] ${data || 'Scan failed'}`)
            setPendingComplete(false)
            setIsScanning(false)
            return
        }
        if (event === 'done') {
            progressTargetRef.current = Math.max(progressTargetRef.current, 100)
            setPendingComplete(true)
        }
    }

    // Animate progress bar through every integer until it reaches server target (min ~3s for 1→100)
    useEffect(() => {
        if (scanView !== 'scanning') return
        const msPerStep = 32
        const id = window.setInterval(() => {
            setDisplayProgress(prev => {
                const cap = Math.min(100, progressTargetRef.current)
                if (prev >= cap) return prev
                return prev + 1
            })
        }, msPerStep)
        return () => window.clearInterval(id)
    }, [scanView])

    useEffect(() => {
        if (!pendingComplete) return
        if (displayProgress < 100) return
        setScanDone(true)
        setPendingComplete(false)
        setIsScanning(false)
    }, [displayProgress, pendingComplete])

    useEffect(() => {
        // keep terminal pinned to bottom while scanning
        if (scanView !== 'scanning') return
        const el = terminalScrollRef.current
        if (!el) return
        el.scrollTop = el.scrollHeight
    }, [terminalLines, scanView])

    useEffect(() => {
        if (activeJobId == null) return
        let cancelled = false
        let timer = 0

        const poll = async () => {
            try {
                const res = await fetch(`/api/jobs/${activeJobId}`)
                const data = await res.json()
                if (cancelled || data.status !== 'success') return
                const job = data.job as AsyncJob
                setJobState(job)
                if (job.status === 'completed' || job.status === 'failed') {
                    window.clearInterval(timer)
                }
            } catch {
                // transient network issue
            }
        }

        void poll()
        timer = window.setInterval(() => {
            void poll()
        }, 1300)
        return () => {
            cancelled = true
            window.clearInterval(timer)
        }
    }, [activeJobId])

    /* ── Load from FileSystem entry (drag-and-drop) ── */
    const loadFromEntry = useCallback(async (entry: FileSystemEntry) => {
        setIsReading(true)
        setLoadError(null)
        setIsLoaded(false)
        setApiResult(null)
        setFolderName(entry.name)
        try {
            const files = await collectFilesFromEntry(entry)
            setUploadFiles(files)
            setClientLangs(detectLangs(files.map(f => f.file.name)))
            setIsLoaded(true)
        } catch {
            setLoadError('Failed to read folder. Try the file picker instead.')
        } finally {
            setIsReading(false)
        }
    }, [])

    /* ── Drag & drop handlers ── */
    const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true) }
    const handleDragLeave = () => setIsDragging(false)
    const handleDrop = async (e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(false)
        const item = e.dataTransfer.items[0]
        if (!item || item.kind !== 'file') return
        const entry = item.webkitGetAsEntry?.()
        if (!entry?.isDirectory) {
            setLoadError('Please drop a project folder, not individual files.')
            return
        }
        await loadFromEntry(entry)
    }

    /* ── File picker (click to browse) ── */
    const handlePickerChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (!e.target.files || !e.target.files.length) return
        const files = Array.from(e.target.files)
        const root = files[0].webkitRelativePath.split('/')[0]
        const collected = files.map(f => ({ file: f, path: f.webkitRelativePath }))
        setFolderName(root)
        setUploadFiles(collected)
        setClientLangs(detectLangs(files.map(f => f.name)))
        setIsLoaded(true)
        setLoadError(null)
        setApiResult(null)
    }

    /* ── Start Analysis: upload files to backend ── */
    const validateServerPath = async () => {
        const p = serverPath.trim()
        if (!p) {
            setPathHint('Enter a directory path.')
            return
        }
        try {
            const res = await fetch('/api/validate-path', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: p }),
            })
            const data = await res.json()
            setPathHint(data.valid ? `Path OK: ${data.resolved}` : (data.message || 'Invalid path'))
        } catch {
            setPathHint('Could not validate path.')
        }
    }

    const startQueuedScan = async () => {
        const p = serverPath.trim()
        if (!p) {
            setLoadError('Please enter a valid project path.')
            return
        }
        setLoadError(null)
        setIsQueueing(true)
        try {
            const res = await fetch('/api/scan-async', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    path: p,
                    scan_mode: selectedMode,
                    load_content: true,
                    incremental: incrementalSemgrep,
                    codeql_enabled: deepCodeql,
                    modules,
                }),
            })
            const data = await res.json()
            if (!res.ok || data.status !== 'success' || typeof data.job_id !== 'number') {
                setLoadError(data.error || 'Failed to queue scan.')
                return
            }
            setActiveJobId(data.job_id as number)
            setJobState(null)
        } catch {
            setLoadError('Cannot connect to API server. Make sure api_server.py is running on port 5001.')
        } finally {
            setIsQueueing(false)
        }
    }

    const handleStartAnalysis = async () => {
        if (scanMethod === 'server') {
            await startQueuedScan()
            return
        }
        if (!isLoaded || uploadFiles.length === 0) {
            setLoadError('Please drop a project folder first.')
            return
        }
        setIsScanning(true)
        setScanView('scanning')
        setScanDone(false)
        setPendingComplete(false)
        progressTargetRef.current = 1
        setDisplayProgress(1)
        setFilesScanned(0)
        setVulnCount(0)
        setProcessCount(0)
        setMaliciousCount(0)
        const nFiles = uploadFiles.length
        setTerminalLines([
            `[--:--.--] Uploading ${nFiles} file(s) to the server…`,
            `[--:--.--] For large projects this step can take a while — the browser is sending the full folder before logs stream.`,
        ])
        setLoadError(null)

        const buildFormData = () => {
            const form = new FormData()
            form.append('scan_mode', selectedMode)
            form.append('folder_name', folderName)
            form.append('incremental', incrementalSemgrep ? '1' : '0')
            form.append('codeql_enabled', deepCodeql ? '1' : '0')
            form.append('modules', JSON.stringify(modules))
            for (const { file, path } of uploadFiles) {
                form.append('files', file)
                form.append('paths', path)
            }
            return form
        }

        try {
            const res = await fetch('/api/upload-scan-stream', { method: 'POST', body: buildFormData() })
            if (!res.ok || !res.body) {
                // fallback to non-stream endpoint (fresh FormData — body can only be read once)
                const r2 = await fetch('/api/upload-scan', { method: 'POST', body: buildFormData() })
                const data: ApiResult = await r2.json()
                setApiResult(data)
                progressTargetRef.current = 100
                setDisplayProgress(100)
                setScanDone(true)
                setIsScanning(false)
                if (data.status !== 'success') setLoadError(data.error || 'Scan failed.')
                return
            }

            // Parse SSE stream manually
            const reader = res.body.getReader()
            const decoder = new TextDecoder()
            let buf = ''

            while (true) {
                const { value, done } = await reader.read()
                if (done) break
                buf += decoder.decode(value, { stream: true })

                // SSE events are separated by blank line
                let idx: number
                while ((idx = buf.indexOf('\n\n')) !== -1) {
                    const raw = buf.slice(0, idx)
                    buf = buf.slice(idx + 2)
                    const lines = raw.split('\n').map(l => l.trimEnd())
                    let ev = 'message'
                    const dataLines: string[] = []
                    for (const line of lines) {
                        if (line.startsWith('event:')) ev = line.slice(6).trim()
                        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart())
                    }
                    const payload = dataLines.join('\n')
                    if (payload.length) handleSseEvent(ev, payload)
                }
            }
        } catch {
            setLoadError('Cannot connect to API server. Make sure api_server.py is running on port 5001.')
            setIsScanning(false)
            setPendingComplete(false)
        }
    }

    const applyModePreset = (modeId: string) => {
        setSelectedMode(modeId)
        const preset = MODE_PRESETS[modeId]
        if (!preset) return
        setModules({ ...preset.modules })
        setIncrementalSemgrep(preset.incrementalSemgrep)
        setDeepCodeql(preset.deepCodeql)
    }
    const activePreset = MODE_PRESETS[selectedMode]
    const isPresetDirty = !!activePreset && (
        incrementalSemgrep !== activePreset.incrementalSemgrep
        || deepCodeql !== activePreset.deepCodeql
        || MODULES.some(mod => Boolean(modules[mod.id]) !== Boolean(activePreset.modules[mod.id]))
    )

    const displayLangs = (apiResult?.model?.languages_detected?.length ?? 0) > 0
        ? apiResult!.model!.languages_detected
        : clientLangs
    const fileCount = uploadFiles.length

    // ── Scanning View (full screen) ───────────────────────────
    if (scanView === 'scanning') {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', flexDirection: 'column' }}>
                <div style={{
                    padding: '20px 32px', borderBottom: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    background: 'rgba(22,27,34,0.70)', backdropFilter: 'blur(20px)',
                    position: 'sticky', top: 0, zIndex: 20,
                }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)' }}>Scan Engine</div>
                    <button className="btn-ghost" onClick={() => navigate('/scan')} style={{ padding: '8px 14px' }}>
                        <ArrowLeft size={16} />Back
                    </button>
                </div>

                <div style={{ flex: 1, padding: '42px 24px 120px', maxWidth: 980, margin: '0 auto', width: '100%' }}>
                    <div style={{ textAlign: 'center', marginBottom: 34 }}>
                        <div style={{
                            width: 52, height: 52, borderRadius: 16,
                            margin: '0 auto 14px',
                            background: 'linear-gradient(135deg, rgba(10,132,255,0.22) 0%, rgba(45,212,191,0.10) 100%)',
                            border: '1px solid rgba(10,132,255,0.25)',
                            boxShadow: '0 0 40px rgba(10,132,255,0.10)',
                        }} />
                        <div style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.02em', marginBottom: 8 }}>
                            Analyzing Application…
                        </div>
                        <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
                            Running {selectedModeLabel.toLowerCase()} with selected modules. Please wait.
                        </div>
                    </div>

                    <div style={{ textAlign: 'center', marginBottom: 24 }}>
                        <div style={{ fontSize: 60, fontWeight: 900, color: 'var(--blue)', letterSpacing: '-0.03em' }}>
                            {displayProgress}%
                        </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 18 }}>
                        {[
                            ['Files Scanned', filesScanned, 'var(--blue)'],
                            ['Vulnerabilities Found', vulnCount, 'var(--red)'],
                            ['Process Events', processCount, 'var(--orange)'],
                            ['Malicious Indicators', maliciousCount, 'var(--red)'],
                        ].map(([label, value, color]) => (
                            <div key={label as string} className="glass-card" style={{ padding: 18, textAlign: 'center' }}>
                                <div style={{ fontSize: 32, fontWeight: 900, color: color as string, marginBottom: 4 }}>
                                    {value as number}
                                </div>
                                <div style={{ fontSize: 12, color: 'var(--text-tertiary)', fontWeight: 600 }}>
                                    {label as string}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Terminal */}
                    <div className="glass-card" style={{ overflow: 'hidden' }}>
                        <div style={{
                            padding: '12px 14px',
                            borderBottom: '1px solid var(--border)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            background: 'rgba(0,0,0,0.18)',
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                <div style={{ display: 'flex', gap: 6 }}>
                                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(255,69,58,0.85)' }} />
                                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(255,159,10,0.85)' }} />
                                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(48,209,88,0.85)' }} />
                                </div>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>scan-engine — bash</div>
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
                                {scanDone ? 'Done' : 'Refreshing…'}
                            </div>
                        </div>
                        <div
                            ref={terminalScrollRef}
                            style={{
                                padding: '14px 16px',
                                maxHeight: 260,
                                overflowY: 'auto',
                                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace',
                                fontSize: 12,
                                lineHeight: 1.7,
                                color: 'var(--text-secondary)',
                                background: 'rgba(0,0,0,0.25)',
                            }}
                        >
                            {terminalLines.map((l, i) => {
                                const isAlert = l.includes('[ALERT]')
                                const isWarn = l.includes('[WARN]') || l.includes('Parse issue') || l.includes('Parse skipped')
                                const isDone = l.toLowerCase().includes('scan complete')
                                const isInfo = l.includes('[INFO]')
                                const tsMatch = l.match(/^\[\d{2}:\d{2}\.\d\]/)
                                const ts = tsMatch ? tsMatch[0] : ''
                                const rest = ts ? l.slice(ts.length).trimStart() : l
                                const baseColor = isDone ? 'var(--green)' : isAlert ? 'var(--red)' : isWarn ? 'var(--orange)' : isInfo ? 'rgba(10,132,255,0.92)' : 'rgba(245,245,247,0.88)'
                                return (
                                    <div key={i} style={{ color: baseColor }}>
                                        {ts ? (
                                            <>
                                                <span style={{ color: 'rgba(10,132,255,0.55)' }}>{ts}</span>
                                                {' '}{rest}
                                            </>
                                        ) : (
                                            l
                                        )}
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                </div>

                {/* Bottom bar */}
                <div style={{
                    position: 'fixed', bottom: 0, left: 0, right: 0, padding: '16px 40px',
                    background: 'rgba(15,17,21,0.85)', backdropFilter: 'blur(20px)',
                    borderTop: '1px solid var(--border)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, zIndex: 30,
                }}>
                    <button className="btn-ghost" onClick={() => navigate('/scan')}>
                        <X size={15} />Cancel
                    </button>

                    <button
                        className="btn-primary"
                        onClick={() => {
                            if (apiResult?.status === 'success' && apiResult.scan_id != null) {
                                navigate(`/dashboard/${apiResult.scan_id}`)
                            }
                        }}
                        disabled={!scanDone || apiResult?.status !== 'success' || apiResult?.scan_id == null}
                        style={{ opacity: (!scanDone || apiResult?.status !== 'success' || apiResult?.scan_id == null) ? 0.55 : 1, minWidth: 170 }}
                    >
                        View Results
                        <ChevronRight size={15} style={{ marginLeft: -4 }} />
                    </button>
                </div>
            </div>
        )
    }

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', flexDirection: 'column' }}>

            {/* Top bar */}
            <div style={{
                padding: '20px 32px', borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', gap: 16,
                background: 'rgba(22,27,34,0.70)', backdropFilter: 'blur(20px)',
                position: 'sticky', top: 0, zIndex: 20,
            }}>
                <button className="btn-ghost" onClick={() => navigate('/')} style={{ padding: '8px 14px' }}>
                    <ArrowLeft size={16} />Back
                </button>
                <div style={{ width: 1, height: 20, background: 'var(--border)' }} />
                <div style={{ fontSize: 14, fontWeight: 600 }}>Scan Configuration</div>
            </div>

            {/* Main content */}
            <div style={{ flex: 1, padding: '36px 32px 120px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>
                <div style={{ marginBottom: 32 }}>
                    <h1 style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 6 }}>
                        Configure Security Scan
                    </h1>
                    <p style={{ color: 'var(--text-secondary)', fontSize: 15 }}>
                        Upload your project folder and configure analysis parameters.
                    </p>
                </div>

                <div className="glass-card" style={{ padding: 18, marginBottom: 18 }}>
                    <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 10 }}>Choose scan method</div>
                    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                        <button
                            type="button"
                            className={scanMethod === 'upload' ? 'btn-primary' : 'btn-secondary'}
                            onClick={() => setScanMethod('upload')}
                            style={{ padding: '10px 14px' }}
                        >
                            Upload Scan
                        </button>
                        <button
                            type="button"
                            className={scanMethod === 'server' ? 'btn-primary' : 'btn-secondary'}
                            onClick={() => setScanMethod('server')}
                            style={{ padding: '10px 14px' }}
                        >
                            <Server size={16} /> Server Path (Queue)
                        </button>
                    </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'start' }}>

                    {/* ─── LEFT COLUMN ─── */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

                        {scanMethod === 'upload' ? (
                            <div className="glass-card" style={{ padding: 24 }}>
                            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>Project Upload</div>

                            {/* Drop zone */}
                            <div
                                className={`drop-zone ${isDragging ? 'drag-over' : ''} ${isLoaded ? 'loaded' : ''}`}
                                onDragOver={handleDragOver}
                                onDragLeave={handleDragLeave}
                                onDrop={handleDrop}
                                onClick={() => fileInputRef.current?.click()}
                                style={{
                                    padding: '48px 24px', textAlign: 'center', cursor: 'pointer',
                                    minHeight: 210, display: 'flex', flexDirection: 'column',
                                    alignItems: 'center', justifyContent: 'center', gap: 14,
                                    userSelect: 'none',
                                }}
                            >
                                {isReading ? (
                                    <>
                                        <div style={{
                                            width: 44, height: 44, borderRadius: '50%',
                                            border: '3px solid rgba(10,132,255,0.2)',
                                            borderTopColor: 'var(--blue)',
                                            animation: 'spin 0.8s linear infinite',
                                        }} />
                                        <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
                                            Reading folder…
                                        </div>
                                    </>
                                ) : isLoaded ? (
                                    <>
                                        <div style={{
                                            width: 54, height: 54, borderRadius: 14,
                                            background: 'rgba(48,209,88,0.12)',
                                            border: '1px solid rgba(48,209,88,0.25)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        }}>
                                            <FolderOpen size={28} color="var(--green)" />
                                        </div>
                                        <div>
                                            <div style={{ color: 'var(--green)', fontWeight: 600, fontSize: 15, marginBottom: 4 }}>
                                                Project loaded successfully
                                            </div>
                                            <div style={{ color: 'rgba(48,209,88,0.70)', fontSize: 13, marginBottom: 4 }}>
                                                {folderName}
                                            </div>
                                            <div style={{ color: 'rgba(48,209,88,0.50)', fontSize: 12 }}>
                                                {fileCount} files · {displayLangs.length} languages detected
                                            </div>
                                        </div>
                                        <div style={{ fontSize: 12, color: 'rgba(48,209,88,0.40)' }}>
                                            Click to change folder
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <div style={{
                                            width: 54, height: 54, borderRadius: 14,
                                            background: 'rgba(255,255,255,0.04)',
                                            border: '1px solid rgba(255,255,255,0.08)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        }}>
                                            <Upload size={26} color="var(--text-tertiary)" />
                                        </div>
                                        <div>
                                            <div style={{ color: 'var(--text-secondary)', fontSize: 15, fontWeight: 500 }}>
                                                Drop your project folder here
                                            </div>
                                            <div style={{ color: 'var(--text-tertiary)', fontSize: 13, marginTop: 4 }}>
                                                or click to browse
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>

                            <input
                                ref={fileInputRef}
                                type="file"
                                // @ts-expect-error webkitdirectory is non-standard
                                webkitdirectory=""
                                directory=""
                                style={{ display: 'none' }}
                                onChange={handlePickerChange}
                            />

                            {/* Error banner */}
                            {loadError && (
                                <div style={{
                                    marginTop: 12, padding: '10px 14px',
                                    background: 'rgba(255,69,58,0.08)', border: '1px solid rgba(255,69,58,0.20)',
                                    borderRadius: 10, fontSize: 13, color: '#FF453A',
                                    display: 'flex', alignItems: 'flex-start', gap: 8,
                                }}>
                                    <AlertCircle size={14} style={{ marginTop: 1, flexShrink: 0 }} />
                                    {loadError}
                                </div>
                            )}

                            {/* Detected languages */}
                            {displayLangs.length > 0 && (
                                <div style={{ marginTop: 16 }}>
                                    <div className="section-label" style={{ marginBottom: 10 }}>Detected Languages</div>
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                        {displayLangs.map(lang => (
                                            <span key={lang} className="lang-chip">{lang}</span>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Post-scan summary */}
                            {apiResult?.status === 'success' && apiResult.model && (
                                <div style={{
                                    marginTop: 16, padding: '14px 16px',
                                    background: 'rgba(48,209,88,0.06)', border: '1px solid rgba(48,209,88,0.15)',
                                    borderRadius: 10,
                                }}>
                                    <div style={{ fontSize: 12, color: 'var(--green)', fontWeight: 600, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                                        <CheckCircle2 size={13} />
                                        Application Model built — Saved to database
                                        {apiResult.scan_id && <span style={{ color: 'rgba(48,209,88,0.5)' }}> (ID #{apiResult.scan_id})</span>}
                                    </div>
                                    <div style={{ display: 'flex', gap: 24 }}>
                                        {[
                                            ['Files', apiResult.model.file_count],
                                            ['Languages', apiResult.model.languages_detected.length],
                                            ['KB', (apiResult.model.total_size_bytes / 1024).toFixed(1)],
                                            ['ms', apiResult.elapsed_ms?.toFixed(0) ?? '—'],
                                        ].map(([label, val]) => (
                                            <div key={label as string}>
                                                <div style={{ fontSize: 20, fontWeight: 700 }}>{val}</div>
                                                <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{label}</div>
                                            </div>
                                        ))}
                                    </div>
                                    {/* Folder tree preview */}
                                    {apiResult.model.folder_structure.length > 0 && (
                                        <div style={{
                                            marginTop: 12, padding: '10px 12px',
                                            background: 'rgba(0,0,0,0.25)', borderRadius: 8,
                                            fontFamily: 'monospace', fontSize: 12,
                                            color: 'var(--text-secondary)', lineHeight: 1.7,
                                            maxHeight: 120, overflowY: 'auto',
                                        }}>
                                            {apiResult.model.folder_structure.slice(0, 12).map((line, i) => (
                                                <div key={i}>{line}</div>
                                            ))}
                                            {apiResult.model.folder_structure.length > 12 && (
                                                <div style={{ color: 'var(--text-tertiary)' }}>
                                                    … {apiResult.model.folder_structure.length - 12} more
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}
                            </div>
                        ) : (
                            <div className="glass-card" style={{ padding: 24 }}>
                                <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 10 }}>Server Path Queue</div>
                                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 12 }}>
                                    Best for very large projects. No browser upload; the backend scans directly from this path.
                                </p>
                                <input
                                    type="text"
                                    value={serverPath}
                                    onChange={e => setServerPath(e.target.value)}
                                    placeholder="e.g. C:\\projects\\my-app"
                                    style={{
                                        width: '100%',
                                        padding: '11px 12px',
                                        borderRadius: 10,
                                        border: '1px solid var(--border)',
                                        background: 'rgba(0,0,0,0.28)',
                                        color: 'var(--text-primary)',
                                        marginBottom: 10,
                                    }}
                                />
                                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
                                    <button type="button" className="btn-ghost" onClick={() => void validateServerPath()}>
                                        Validate Path
                                    </button>
                                    {pathHint && (
                                        <span style={{ fontSize: 12, color: pathHint.startsWith('Path OK') ? 'var(--green)' : 'var(--orange)' }}>
                                            {pathHint}
                                        </span>
                                    )}
                                </div>
                                {activeJobId != null && (
                                    <div style={{ marginTop: 12, padding: 12, borderRadius: 10, background: 'rgba(0,0,0,0.24)', border: '1px solid var(--border)' }}>
                                        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-tertiary)', marginBottom: 6 }}>
                                            Job #{activeJobId}
                                        </div>
                                        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>
                                            Status: <strong style={{ color: 'var(--text-primary)' }}>{jobState?.status || 'queued'}</strong>
                                        </div>
                                        {jobState?.codeql_enabled ? (
                                            <div style={{ fontSize: 11, color: '#7db7ff', marginBottom: 8 }}>
                                                Deep scan (CodeQL): enabled
                                            </div>
                                        ) : null}
                                        {jobState?.status === 'failed' && jobState.error_message ? (
                                            <div style={{ fontSize: 12, color: '#FF453A', marginBottom: 8 }}>{jobState.error_message}</div>
                                        ) : null}
                                        {jobState?.status === 'completed' && jobState.result_scan_id != null ? (
                                            <button
                                                type="button"
                                                className="btn-primary"
                                                onClick={() => navigate(`/dashboard/${jobState.result_scan_id}/reports`)}
                                            >
                                                Open Report
                                            </button>
                                        ) : null}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Incremental Semgrep (streaming upload only) */}
                        <div className="glass-card" style={{ padding: 24 }}>
                            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>Semgrep</div>
                            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 14 }}>
                                The server always runs broad community SAST packs (OWASP, CWE, injections, secrets, multi-language)
                                on every scan when static analysis is enabled — there is no separate “maximum Semgrep” toggle.
                                Optional: set <code>SAST_SEMGREP_PROFILE=balanced</code> on the API host for a lighter, faster run.
                            </p>
                            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 14 }}>
                                {scanMethod === 'upload'
                                    ? 'Incremental cache: when enabled, unchanged projects can reuse cached Semgrep results. Uploaded folders use a new temp path each run, so cache hits are unlikely unless you scan the same directory on the server (see Telemetry & Queue).'
                                    : 'Incremental cache: when enabled for server-path scans, unchanged projects can reuse cached Semgrep results and usually run much faster on repeat scans.'}
                            </p>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                                <span style={{ fontSize: 14, fontWeight: 600 }}>Incremental Semgrep</span>
                                <Toggle on={incrementalSemgrep} onToggle={() => setIncrementalSemgrep(p => !p)} />
                            </div>
                        </div>

                        <div className="glass-card" style={{ padding: 24 }}>
                            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>Deep scan option</div>
                            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 14 }}>
                                Enable CodeQL for deeper dataflow analysis (slower, but higher precision on supported languages).
                            </p>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                                <span style={{ fontSize: 14, fontWeight: 600 }}>Deep scan (CodeQL on)</span>
                                <Toggle on={deepCodeql} onToggle={() => setDeepCodeql(p => !p)} />
                            </div>
                        </div>

                        {/* Scan Mode */}
                        <div className="glass-card" style={{ padding: 24 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 16 }}>
                                <div style={{ fontSize: 15, fontWeight: 600 }}>Scan Mode</div>
                                {isPresetDirty ? (
                                    <span
                                        style={{
                                            fontSize: 11,
                                            fontWeight: 700,
                                            letterSpacing: '0.02em',
                                            color: '#ffd66b',
                                            background: 'rgba(255,214,107,0.12)',
                                            border: '1px solid rgba(255,214,107,0.34)',
                                            borderRadius: 999,
                                            padding: '4px 10px',
                                        }}
                                    >
                                        Preset modified
                                    </span>
                                ) : null}
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {SCAN_MODES.map(mode => (
                                    <div
                                        key={mode.id}
                                        className={`scan-mode-card ${selectedMode === mode.id ? 'selected' : ''}`}
                                        onClick={() => applyModePreset(mode.id)}
                                        title={presetSummary(mode.id)}
                                    >
                                        <div>
                                            <div style={{ fontSize: 14, fontWeight: 600, color: selectedMode === mode.id ? 'var(--blue)' : 'var(--text-primary)', marginBottom: 2 }}>
                                                {mode.label}
                                            </div>
                                            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{mode.description}</div>
                                        </div>
                                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-tertiary)', background: 'rgba(255,255,255,0.06)', padding: '4px 10px', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                                            <Clock size={11} />{mode.time}
                                        </div>
                                    </div>
                                ))}
                            </div>
                            <div style={{ marginTop: 12, display: 'flex', justifyContent: 'flex-end' }}>
                                <button
                                    type="button"
                                    className="btn-ghost"
                                    onClick={() => applyModePreset(selectedMode)}
                                    disabled={!isPresetDirty}
                                    style={{ opacity: isPresetDirty ? 1 : 0.55 }}
                                >
                                    Reset to preset
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* ─── RIGHT COLUMN — modules ─── */}
                    <div className="glass-card" style={{ padding: 24 }}>
                        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>Analysis Modules</div>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            {MODULES.map((mod, idx) => (
                                <div key={mod.id} style={{
                                    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
                                    gap: 16, padding: '16px 0',
                                    borderBottom: idx < MODULES.length - 1 ? '1px solid var(--border)' : 'none',
                                }}>
                                    <div style={{ flex: 1 }}>
                                        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 3 }}>{mod.label}</div>
                                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{mod.description}</div>
                                    </div>
                                    <div style={{ paddingTop: 2 }}>
                                        <Toggle on={modules[mod.id]} onToggle={() => setModules(p => ({ ...p, [mod.id]: !p[mod.id] }))} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Fixed bottom action bar */}
            <div style={{
                position: 'fixed', bottom: 0, left: 0, right: 0, padding: '16px 40px',
                background: 'rgba(15,17,21,0.85)', backdropFilter: 'blur(20px)',
                borderTop: '1px solid var(--border)',
                display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 12, zIndex: 30,
            }}>
                <button className="btn-ghost" onClick={() => navigate('/')}>
                    <X size={15} />Cancel
                </button>
                <button
                    className="btn-primary"
                    onClick={handleStartAnalysis}
                    disabled={
                        scanMethod === 'upload'
                            ? (isScanning || !isLoaded)
                            : (isQueueing || !serverPath.trim())
                    }
                    style={{
                        opacity: (
                            scanMethod === 'upload'
                                ? (isScanning || !isLoaded)
                                : (isQueueing || !serverPath.trim())
                        ) ? 0.55 : 1,
                        minWidth: 170,
                    }}
                >
                    {scanMethod === 'upload' ? (
                        isScanning ? (
                            <>
                                <div style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.4)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
                                Uploading & Scanning…
                            </>
                        ) : (
                            <>
                                <Play size={16} fill="currentColor" />
                                Start Analysis
                                <ChevronRight size={15} style={{ marginLeft: -4 }} />
                            </>
                        )
                    ) : (
                        isQueueing ? (
                            <>
                                <div style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.4)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
                                Queueing…
                            </>
                        ) : (
                            <>
                                <Server size={16} />
                                Queue Scan
                                <ChevronRight size={15} style={{ marginLeft: -4 }} />
                            </>
                        )
                    )}
                </button>
            </div>

            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
    )
}
