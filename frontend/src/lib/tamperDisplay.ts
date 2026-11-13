export interface TamperIssue {
    file: string
    line: number
    type: string
    risk: string
    evidence: string
    score: number
}

const RISK_ORDER: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 }

export function maxRisk(risks: string[]): string {
    let best = 'Low'
    let o = 0
    for (const r of risks) {
        const v = RISK_ORDER[r] ?? 0
        if (v > o) {
            o = v
            best = r
        }
    }
    return best
}

/** Tamper resistance 0–100% (higher = better). Derived from cumulative tamper burden. */
export function tamperResistancePct(issues: TamperIssue[]): number {
    const burden = issues.reduce((s, t) => s + (t.score || 0), 0)
    return Math.max(0, Math.min(100, 100 - Math.min(100, burden)))
}

export function resistanceLabel(pct: number): { text: string; color: string; badgeBg: string } {
    if (pct >= 70) return { text: 'High Tamper Resistance', color: '#30D158', badgeBg: 'rgba(48,209,88,0.2)' }
    if (pct >= 45) return { text: 'Medium Tamper Resistance', color: '#FF9F0A', badgeBg: 'rgba(255,159,10,0.2)' }
    return { text: 'Low Tamper Resistance', color: '#FF453A', badgeBg: 'rgba(255,69,58,0.22)' }
}

export interface TamperGroup {
    type: string
    count: number
    maxRisk: string
    items: TamperIssue[]
    description: string
}

export function groupTamperIssues(issues: TamperIssue[]): TamperGroup[] {
    const m = new Map<string, TamperIssue[]>()
    for (const t of issues) {
        if (!m.has(t.type)) m.set(t.type, [])
        m.get(t.type)!.push(t)
    }
    return Array.from(m.entries()).map(([type, items]) => ({
        type,
        count: items.length,
        maxRisk: maxRisk(items.map(i => i.risk)),
        items,
        description: whyTamperable(type, items),
    }))
}

function whyTamperable(type: string, items: TamperIssue[]): string {
    const fileNames = [...new Set(items.map(i => i.file.replace(/\\/g, '/').split('/').pop() || i.file))].slice(0, 12)
    const list = fileNames.join(', ')
    const t = type.toLowerCase()
    if (t.includes('exposed config'))
        return `Configuration files (${list}) are present and may be reachable via HTTP, version control, or deployment artifacts. Tampering with these paths can change secrets, database URLs, or feature flags without code changes.`
    if (t.includes('debug'))
        return `Debug flags expose stack traces, Werkzeug consoles, or verbose errors (${list}). An attacker can learn internals and pivot to authenticated surfaces.`
    if (t.includes('admin') || t.includes('role'))
        return `Hardcoded privilege flags (${list}) weaken authorization boundaries; values can be patched in place or toggled via file tampering.`
    if (t.includes('writable'))
        return `Writable opens on sensitive paths (${list}) allow planting trojan configs or credential files that the app will load on next run.`
    if (t.includes('environment'))
        return `Heavy reliance on environment variables enables override via process environment, service files, or container entrypoints—raising injection and library preload risk.`
    return `Issues of type “${type}” affect: ${list}. Local or remote tampering with these artifacts can change runtime behavior without modifying shipped binaries.`
}

export interface RuntimeBar {
    label: string
    pct: number
    color: string
}

/** Map tamper issues + scan risk into five “runtime manipulation” dimensions (higher = worse). */
export function runtimeManipulationBars(issues: TamperIssue[], riskScore: number | null): RuntimeBar[] {
    const rs = riskScore ?? 0
    let lib = 0
    let cfg = 0
    let proc = 0
    let fs = 0
    for (const t of issues) {
        const s = t.score || 0
        const ty = t.type.toLowerCase()
        if (ty.includes('environment')) lib += s
        else if (ty.includes('exposed') || ty.includes('config')) cfg += s
        else if (ty.includes('debug') || ty.includes('admin') || ty.includes('role')) proc += s
        else if (ty.includes('writable')) fs += s
        else {
            cfg += s * 0.5
            proc += s * 0.5
        }
    }
    const scale = (v: number, fallback: number) => Math.min(100, Math.max(12, Math.round(v * 2.4 + fallback * 0.25 + rs * 0.15)))

    return [
        { label: 'Library Injection Risk', pct: scale(lib, 28), color: '#FFD60A' },
        { label: 'Config Override Risk', pct: scale(cfg, 32), color: '#FF453A' },
        { label: 'Process Manipulation', pct: scale(proc, 24), color: '#FF9F0A' },
        { label: 'Memory Safety', pct: Math.min(100, Math.max(18, Math.round(38 + rs * 0.22 + (issues.length ? 0 : 5)))), color: '#FF453A' },
        { label: 'File System Integrity', pct: scale(fs, 26), color: '#FF9F0A' },
    ]
}

export function assessmentSummary(resistancePct: number, issues: TamperIssue[], riskLevel: string | null): string {
    const level = (riskLevel || 'Unknown').toLowerCase()
    const critBits: string[] = []
    const types = new Set(issues.map(i => i.type))
    if (types.has('Debug Mode Enabled')) critBits.push('debug mode in production')
    if ([...types].some(t => t.includes('Exposed Config'))) critBits.push('exposed configuration files')
    if ([...types].some(t => t.includes('Writable'))) critBits.push('writable sensitive paths')
    if ([...types].some(t => t.includes('Admin'))) critBits.push('hardcoded privilege flags')
    if ([...types].some(t => t.includes('Environment'))) critBits.push('environment-driven configuration')

    const strength = resistancePct >= 70 ? 'strong' : resistancePct >= 45 ? 'moderate' : 'low'
    const tail =
        critBits.length > 0
            ? ` Notable exposure includes ${critBits.slice(0, 3).join(', ')}${critBits.length > 3 ? ', and related vectors' : ''}.`
            : ' Review deployment hardening and integrity checks for this codebase.'

    return `The application demonstrates **${strength} tamper resistance** relative to this scan (overall posture: ${level} project risk).${tail}`
}

export function severityStyleTamper(risk: string): { bg: string; color: string } {
    const r = (risk || '').toLowerCase()
    if (r === 'critical') return { bg: 'rgba(255,69,58,0.22)', color: '#FF453A' }
    if (r === 'high') return { bg: 'rgba(255,159,10,0.18)', color: '#FF9F0A' }
    if (r === 'medium') return { bg: 'rgba(255,214,10,0.12)', color: '#FFD60A' }
    return { bg: 'rgba(10,132,255,0.12)', color: '#0A84FF' }
}
