/**
 * Derive node kinds (function / system / risky), risky paths, and edge labels
 * from process_graph + process_events (SQLite / API).
 */

export interface ProcEv {
    file: string
    line: number
    type: string
    function: string
    risk: string
    tainted: boolean
    detail?: string
}

export interface RawEdge {
    from: string
    to: string
    file?: string | null
}

export type NodeKind = 'function' | 'system' | 'risky'

const RISKY_ID = /exec|eval|subprocess|os\.system|popen|shell|\/bin|powershell|socket\.|connect|bind|child|tainted flow|reverse/i
const SYSTEM_ID = /subprocess|os\.|socket|urllib|requests|httpx|pathlib|open\(|sys\.|shutil/i
const SOURCE_ID = /^input\(\)$|^tainted$|stdin|argv|request|readline/i

function normFn(s: string) {
    return s.split('(')[0].trim().toLowerCase()
}

/** Nodes that process_events associate with tainted / high-risk behavior. */
function nodesFromEvents(nodes: string[], events: ProcEv[]): Set<string> {
    const out = new Set<string>()
    for (const ev of events) {
        const fn = normFn(ev.function)
        for (const n of nodes) {
            const nl = n.toLowerCase()
            if (nl === fn || nl.includes(fn) || fn.includes(nl) || n === ev.function) out.add(n)
        }
        if (ev.tainted || ev.risk === 'High' || ev.risk === 'Critical') {
            for (const n of nodes) {
                if (RISKY_ID.test(n)) out.add(n)
            }
        }
    }
    return out
}

function classifyNode(nodeId: string, eventRiskyHints: Set<string>): NodeKind {
    if (eventRiskyHints.has(nodeId) || RISKY_ID.test(nodeId)) return 'risky'
    if (SYSTEM_ID.test(nodeId) && !SOURCE_ID.test(nodeId)) return 'system'
    return 'function'
}

function sourceNodes(nodes: string[]): Set<string> {
    const s = new Set<string>()
    for (const n of nodes) {
        if (SOURCE_ID.test(n) || n.toLowerCase().includes('input')) s.add(n)
    }
    return s
}

function isTaintSource(id: string): boolean {
    const l = id.toLowerCase()
    return l === 'tainted' || l === 'input()' || l.includes('input')
}

function reachableFrom(sources: Set<string>, edges: RawEdge[]): Set<string> {
    const adj = new Map<string, string[]>()
    for (const e of edges) {
        if (e.from === e.to) continue
        if (!adj.has(e.from)) adj.set(e.from, [])
        adj.get(e.from)!.push(e.to)
    }
    const seen = new Set<string>()
    const stack = [...sources]
    for (const s of sources) seen.add(s)
    while (stack.length) {
        const u = stack.pop()!
        for (const v of adj.get(u) || []) {
            if (!seen.has(v)) {
                seen.add(v)
                stack.push(v)
            }
        }
    }
    return seen
}

export interface EnrichedEdge extends RawEdge {
    id: string
    risky: boolean
    label: string
}

export interface EnrichedNode {
    id: string
    kind: NodeKind
    title: string
    subtitle: string
}

function edgeLabel(from: string, to: string, risky: boolean): string {
    if (risky) {
        const tl = to.toLowerCase()
        if (tl.includes('subprocess') || tl.includes('os.system') || tl.includes('popen')) return 'tainted data'
        if (tl.includes('socket') || tl.includes('connect')) return 'connects'
        if (tl.includes('exec') || tl.includes('eval')) return 'executes'
        return 'tainted flow'
    }
    if (/input|^tainted$/i.test(from)) return 'flows'
    return 'calls'
}

/** Short subtitle: file from first edge that touches this node, or node id hint. */
function subtitleForNode(nodeId: string, edges: RawEdge[]): string {
    for (const e of edges) {
        if (e.from === nodeId || e.to === nodeId) {
            const f = e.file
            if (f) {
                const base = f.replace(/\\/g, '/').split('/').pop() || f
                return base
            }
        }
    }
    if (nodeId.includes('()')) return nodeId
    return nodeId.length > 42 ? nodeId.slice(0, 40) + '…' : nodeId
}

export function buildProcessGraphView(
    nodes: string[],
    edges: RawEdge[],
    processEvents: ProcEv[],
): { nodes: EnrichedNode[]; edges: EnrichedEdge[]; stats: { riskyNodes: number; riskyEdges: number } } {
    const eventHints = nodesFromEvents(nodes, processEvents)
    const kinds = new Map<string, NodeKind>()
    for (const n of nodes) kinds.set(n, classifyNode(n, eventHints))

    const riskyNodeSet = new Set(nodes.filter(n => kinds.get(n) === 'risky'))
    const sources = sourceNodes(nodes)
    const reach = reachableFrom(sources, edges)

    const enrichedEdges: EnrichedEdge[] = edges.map((e, i) => {
        const toIsSink = riskyNodeSet.has(e.to) || RISKY_ID.test(e.to)
        const directTaintToSink =
            e.from !== e.to && isTaintSource(e.from) && toIsSink
        const chainRisk =
            e.from !== e.to &&
            riskyNodeSet.has(e.to) &&
            (reach.has(e.from) || riskyNodeSet.has(e.from))
        const risky = Boolean(directTaintToSink || chainRisk)
        return {
            ...e,
            id: `e-${i}-${e.from}-${e.to}`,
            risky,
            label: edgeLabel(e.from, e.to, risky),
        }
    })

    const enrichedNodes: EnrichedNode[] = nodes.map(n => ({
        id: n,
        kind: kinds.get(n)!,
        title: n.length > 48 ? n.slice(0, 46) + '…' : n,
        subtitle: subtitleForNode(n, edges),
    }))

    const riskyEdges = enrichedEdges.filter(e => e.risky).length
    return {
        nodes: enrichedNodes,
        edges: enrichedEdges,
        stats: { riskyNodes: riskyNodeSet.size, riskyEdges },
    }
}
