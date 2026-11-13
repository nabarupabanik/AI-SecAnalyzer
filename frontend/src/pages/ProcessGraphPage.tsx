import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import dagre from 'dagre'
import {
    ReactFlow,
    Background,
    Controls,
    MiniMap,
    Panel,
    useReactFlow,
    ReactFlowProvider,
    MarkerType,
    Position,
    Handle,
    useNodesState,
    useEdgesState,
    useViewport,
    useNodesInitialized,
    type Node,
    type Edge,
    type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Maximize2, Minus, Plus } from 'lucide-react'
import DashboardSidebar from '../components/DashboardSidebar'
import { buildProcessGraphView, type NodeKind, type ProcEv } from '../lib/processGraphModel'

interface ScanPayload {
    id: number
    project_path: string
    languages?: string[]
    process_graph: { nodes: string[]; edges: { from: string; to: string; file?: string | null }[] }
    process_events: ProcEv[]
    taint_paths?: {
        source: string
        sink: string
        file: string
        line: number
        severity: string
        confidence?: string
        sanitized?: boolean
        category?: string
        evidence?: string
        count?: number
        line_samples?: number[]
    }[]
}

const NODE_W = 220
const NODE_H = 92

type FlowNodeData = { title: string; subtitle: string; kind: NodeKind }
type TaintPathRow = {
    source: string
    sink: string
    file: string
    line: number
    severity: string
    confidence?: string
    sanitized?: boolean
    category?: string
    evidence?: string
    count?: number
    line_samples?: number[]
    badges?: string[]
}

function deriveRiskBadges(ev: { sink?: string; evidence?: string; category?: string }): string[] {
    const s = `${ev.sink || ''} ${ev.evidence || ''}`.toLowerCase()
    const out: string[] = []
    if (s.includes('cross_file=true') || s.includes('cross-file') || s.includes('cross_file')) out.push('cross-file')
    if (s.includes('interprocedural') || s.includes('wrapper=')) out.push('interprocedural')
    if (s.includes('behavior_chain_score=') || s.includes('correlation')) out.push('correlated')
    if ((ev.category || '').toLowerCase() === 'system') out.push('sink')
    return Array.from(new Set(out))
}

function ProcessFlowNode({ data }: NodeProps<Node<FlowNodeData>>) {
    const { title, subtitle, kind } = data
    const border =
        kind === 'risky'
            ? 'rgba(255,69,58,0.85)'
            : kind === 'system'
              ? 'rgba(10,132,255,0.75)'
              : 'rgba(255,255,255,0.18)'
    const bg =
        kind === 'risky'
            ? 'rgba(60,20,22,0.95)'
            : kind === 'system'
              ? 'rgba(12,28,48,0.92)'
              : 'rgba(38,38,44,0.92)'

    return (
        <>
            <Handle type="target" position={Position.Left} style={{ background: border, width: 8, height: 8 }} />
            <div
                style={{
                    minWidth: NODE_W - 24,
                    maxWidth: 280,
                    padding: '12px 14px',
                    borderRadius: 10,
                    border: `1.5px solid ${border}`,
                    background: bg,
                    boxShadow: kind === 'risky' ? '0 0 20px rgba(255,69,58,0.15)' : 'none',
                }}
            >
                <div style={{ fontWeight: 700, fontSize: 13, color: '#f5f5f7', lineHeight: 1.3 }}>{title}</div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, fontFamily: 'ui-monospace, monospace' }}>
                    {subtitle}
                </div>
            </div>
            <Handle type="source" position={Position.Right} style={{ background: border, width: 8, height: 8 }} />
        </>
    )
}

const nodeTypes = { processNode: ProcessFlowNode }

function layoutDagre(nodes: Node<FlowNodeData>[], edges: Edge[]): Node<FlowNodeData>[] {
    if (nodes.length === 0) return nodes
    const g = new dagre.graphlib.Graph()
    g.setDefaultEdgeLabel(() => ({}))
    g.setGraph({ rankdir: 'LR', nodesep: 48, ranksep: 64, marginx: 24, marginy: 24 })

    nodes.forEach(n => g.setNode(n.id, { width: NODE_W, height: NODE_H }))
    edges.forEach(e => {
        if (e.source !== e.target) g.setEdge(e.source, e.target)
    })

    dagre.layout(g)

    return nodes.map(n => {
        const pos = g.node(n.id)
        if (!pos) return { ...n, position: { x: 0, y: 0 } }
        return {
            ...n,
            position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 },
            sourcePosition: Position.Right,
            targetPosition: Position.Left,
        }
    })
}

function buildFlowElements(scan: ScanPayload): { nodes: Node<FlowNodeData>[]; edges: Edge[] } {
    const pg = scan.process_graph || { nodes: [], edges: [] }
    const rawEdges = (pg.edges || []).filter(e => e.from && e.to)
    const enriched = buildProcessGraphView(pg.nodes || [], rawEdges, scan.process_events || [])

    const nodes: Node<FlowNodeData>[] = enriched.nodes.map(n => ({
        id: n.id,
        type: 'processNode',
        position: { x: 0, y: 0 },
        data: { title: n.title, subtitle: n.subtitle, kind: n.kind },
    }))

    const edges: Edge[] = enriched.edges.map(e => ({
        id: e.id,
        source: e.from,
        target: e.to,
        label: e.label,
        animated: e.risky,
        style: {
            stroke: e.risky ? '#FF453A' : 'rgba(245,245,247,0.42)',
            strokeWidth: e.risky ? 2.2 : 1.4,
        },
        strokeDasharray: e.risky ? '6 4' : undefined,
        markerEnd: {
            type: MarkerType.ArrowClosed,
            color: e.risky ? '#FF453A' : 'var(--text-tertiary)',
            width: 18,
            height: 18,
        },
        labelStyle: { fill: e.risky ? '#FF453A' : 'var(--text-tertiary)', fontSize: 11, fontWeight: 600 },
        labelBgStyle: { fill: 'rgba(18,18,22,0.92)', fillOpacity: 0.95 },
        labelBgPadding: [4, 6] as [number, number],
    }))

    const laid = layoutDagre(nodes, edges)
    return { nodes: laid, edges }
}

function ZoomReadout() {
    const { zoom } = useViewport()
    return (
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', minWidth: 48, textAlign: 'center' }}>
            {Math.round(zoom * 100)}%
        </span>
    )
}

function GraphCanvas({ scan }: { scan: ScanPayload }) {
    const { fitView, zoomIn, zoomOut } = useReactFlow()
    const containerRef = useRef<HTMLDivElement>(null)
    const initial = useMemo(() => buildFlowElements(scan), [scan])
    const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes)
    const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges)
    const nodesInit = useNodesInitialized({ includeHiddenNodes: false })

    useEffect(() => {
        const next = buildFlowElements(scan)
        setNodes(next.nodes)
        setEdges(next.edges)
    }, [scan, setNodes, setEdges])

    useEffect(() => {
        if (nodesInit && nodes.length > 0) {
            const t = window.setTimeout(() => fitView({ padding: 0.15, duration: 280 }), 80)
            return () => clearTimeout(t)
        }
    }, [nodesInit, nodes.length, fitView, scan.id])

    const onFullscreen = useCallback(() => {
        const el = containerRef.current
        if (!el) return
        if (!document.fullscreenElement) el.requestFullscreen?.()
        else document.exitFullscreen?.()
    }, [])

    return (
        <div
            ref={containerRef}
            className="process-graph-canvas"
            style={{
                flex: 1,
                minHeight: 420,
                borderRadius: 14,
                border: '1px solid rgba(255,255,255,0.08)',
                background: 'rgba(22,22,28,0.65)',
                overflow: 'hidden',
            }}
        >
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                fitView
                minZoom={0.15}
                maxZoom={1.8}
                proOptions={{ hideAttribution: true }}
            >
                <Background color="rgba(255,255,255,0.06)" gap={20} />
                <Controls
                    showInteractive={false}
                    style={{ background: 'rgba(30,30,36,0.9)', border: '1px solid rgba(255,255,255,0.1)' }}
                />
                <MiniMap
                    nodeStrokeWidth={2}
                    zoomable
                    pannable
                    style={{ background: 'rgba(12,12,16,0.85)' }}
                    maskColor="rgba(0,0,0,0.45)"
                />
                <Panel position="top-right" style={{ margin: 12 }}>
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                            padding: '6px 10px',
                            borderRadius: 10,
                            background: 'rgba(30,30,36,0.95)',
                            border: '1px solid rgba(255,255,255,0.08)',
                        }}
                    >
                        <button
                            type="button"
                            className="btn-ghost"
                            onClick={() => zoomOut({ duration: 200 })}
                            style={{ padding: 8, borderRadius: 8 }}
                            aria-label="Zoom out"
                        >
                            <Minus size={18} />
                        </button>
                        <ZoomReadout />
                        <button
                            type="button"
                            className="btn-ghost"
                            onClick={() => zoomIn({ duration: 200 })}
                            style={{ padding: 8, borderRadius: 8 }}
                            aria-label="Zoom in"
                        >
                            <Plus size={18} />
                        </button>
                        <button
                            type="button"
                            className="btn-ghost"
                            onClick={onFullscreen}
                            style={{ padding: 8, borderRadius: 8 }}
                            aria-label="Fullscreen"
                        >
                            <Maximize2 size={18} />
                        </button>
                    </div>
                </Panel>
            </ReactFlow>
        </div>
    )
}

function LegendRow({ color, label, sub }: { color: string; label: string; sub: string }) {
    return (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0 }} />
            <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{label}</div>
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{sub}</div>
            </div>
        </div>
    )
}

function LegendLine({ dashed, label, color = 'var(--text-secondary)' }: { dashed: boolean; label: string; color?: string }) {
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <svg width={36} height={10} style={{ flexShrink: 0 }}>
                <line x1={2} y1={5} x2={34} y2={5} stroke={color} strokeWidth={2} strokeDasharray={dashed ? '5 4' : undefined} />
            </svg>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{label}</span>
        </div>
    )
}

function ProcessGraphMain({ scan }: { scan: ScanPayload }) {
    const stats = useMemo(() => {
        const pg = scan.process_graph || { nodes: [], edges: [] }
        return { n: (pg.nodes || []).length, e: (pg.edges || []).length }
    }, [scan])
    const riskyEvents = useMemo<TaintPathRow[]>(() => {
        const sevRank = (s: string) => ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[s] || 0)
        const confRank = (c?: string) => ({ High: 3, Medium: 2, Low: 1 }[(c || 'Medium') as 'High' | 'Medium' | 'Low'] || 0)

        const tp: TaintPathRow[] = [...(scan.taint_paths || [])]
        if (tp.length > 0) {
            tp.sort((a, b) => {
                const s = sevRank(b.severity) - sevRank(a.severity)
                if (s) return s
                const c = confRank(b.confidence) - confRank(a.confidence)
                if (c) return c
                const n = (b.count || 1) - (a.count || 1)
                if (n) return n
                return (a.file || '').localeCompare(b.file || '') || (a.line || 0) - (b.line || 0)
            })
            return tp.slice(0, 8)
        }
        const fallback: TaintPathRow[] = (scan.process_events || [])
            .filter(ev => ev.tainted || ev.risk === 'High' || ev.risk === 'Critical')
            .map(ev => ({
                source: 'tainted-input',
                sink: ev.function,
                file: ev.file,
                line: ev.line,
                severity: ev.risk,
                confidence: /confidence=high/i.test(ev.detail || '') ? 'High' : /confidence=low/i.test(ev.detail || '') ? 'Low' : 'Medium',
                sanitized: /sanitized=true|parameterized=true/i.test(ev.detail || ''),
                category: 'system',
                evidence: ev.detail,
                badges: deriveRiskBadges({ sink: ev.function, evidence: ev.detail, category: 'system' }),
            }))
        fallback.sort((a, b) => {
            const s = sevRank(b.severity) - sevRank(a.severity)
            if (s) return s
            return confRank(b.confidence) - confRank(a.confidence)
        })
        return fallback.slice(0, 8)
    }, [scan.process_events, scan.taint_paths])

    return (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--bg-primary)' }}>
            <div style={{ marginBottom: 16 }}>
                <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 6 }}>Process Behavior Graph</h1>
                <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                    Interactive call graph and process flow. Hover nodes for details.
                </p>
                <p style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 8 }}>
                    Nodes: {stats.n} · Edges: {stats.e}
                </p>
            </div>

            <div style={{ display: 'flex', gap: 16, flex: 1, minHeight: 420 }}>
                <ReactFlowProvider>
                    <GraphCanvas scan={scan} />
                </ReactFlowProvider>

                <aside
                    style={{
                        width: 220,
                        flexShrink: 0,
                        padding: 18,
                        borderRadius: 14,
                        background: 'rgba(28,28,34,0.95)',
                        border: '1px solid rgba(255,255,255,0.08)',
                        alignSelf: 'stretch',
                    }}
                >
                    <div style={{ fontSize: 12, fontWeight: 800, letterSpacing: '0.06em', color: 'var(--text-secondary)', marginBottom: 14 }}>
                        LEGEND
                    </div>
                    <LegendRow color="var(--text-secondary)" label="Functions" sub="Application code" />
                    <LegendRow color="#0A84FF" label="System calls" sub="OS / library" />
                    <LegendRow color="#FF453A" label="Risky nodes" sub="Critical sinks & taint" />
                    <div style={{ height: 1, background: 'rgba(255,255,255,0.08)', margin: '14px 0' }} />
                    <LegendLine dashed={false} label="Normal flow" />
                    <LegendLine dashed label="Risky path" color="#FF453A" />
                </aside>
            </div>

            <section
                style={{
                    marginTop: 16,
                    borderRadius: 14,
                    border: '1px solid rgba(255,255,255,0.08)',
                    background: 'rgba(28,28,34,0.9)',
                    padding: 16,
                }}
            >
                <div style={{ fontSize: 12, fontWeight: 800, letterSpacing: '0.06em', color: 'var(--text-secondary)', marginBottom: 10 }}>
                    RISKY PATH EXPLANATIONS
                </div>
                {riskyEvents.length === 0 ? (
                    <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>No high-risk taint paths were detected in this scan.</div>
                ) : (
                    <div style={{ display: 'grid', gap: 8 }}>
                        {riskyEvents.map((ev, i) => (
                            <div key={`${ev.file}-${ev.line}-${ev.sink}-${i}`} style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                                <span style={{ color: '#FF9F0A', fontWeight: 700 }}>{ev.severity}</span>
                                {' - '}
                                <span style={{ fontFamily: 'ui-monospace, monospace' }}>{ev.source}{' -> '}{ev.sink}</span>
                                {ev.badges && ev.badges.length > 0 ? (
                                    <span style={{ marginLeft: 8, display: 'inline-flex', gap: 6, flexWrap: 'wrap', verticalAlign: 'middle' }}>
                                        {ev.badges.map(b => (
                                            <span
                                                key={b}
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
                                ) : null}
                                {ev.confidence ? (
                                    <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                                        [{ev.confidence} confidence]
                                    </span>
                                ) : null}
                                {' at '}
                                <span>{ev.file.replace(/\\/g, '/')}:{ev.line}</span>
                                {ev.count && ev.count > 1 ? (
                                    <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                                        ({ev.count} occurrences)
                                    </span>
                                ) : null}
                                {ev.evidence ? (
                                    <span style={{ color: 'var(--text-secondary)' }}>{` -> ${ev.evidence}`}</span>
                                ) : null}
                            </div>
                        ))}
                    </div>
                )}
            </section>
        </div>
    )
}

export default function ProcessGraphPage() {
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

    if (loading) {
        return (
            <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                Loading process graph…
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

    const empty = !(scan.process_graph?.nodes?.length || scan.process_graph?.edges?.length)

    return (
        <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', display: 'flex', color: '#F5F5F7' }}>
            <DashboardSidebar scanId={scanId} active="process-graph" />
            <main style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '32px 40px 40px', minWidth: 0 }}>
                {empty ? (
                    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                        No process graph edges were generated for this scan.
                        <div style={{ marginTop: 10, maxWidth: 620, lineHeight: 1.6, fontSize: 13, color: 'var(--text-tertiary)' }}>
                            Common causes: (1) your repo has no readable Python/JS source (very large/minified/unsupported files), (2) the scan ran in structure-only mode, or (3) the code doesn&apos;t match the heuristic sources/sinks we look for (Express `req.*` + `child_process`/`eval` style calls).
                            {scan.languages && scan.languages.length ? (
                                <span>
                                    {' '}
                                    Languages detected: <strong style={{ color: 'var(--text-secondary)' }}>{scan.languages.join(', ')}</strong>.
                                </span>
                            ) : null}
                        </div>
                    </div>
                ) : (
                    <ProcessGraphMain key={scan.id} scan={scan} />
                )}
            </main>
        </div>
    )
}
