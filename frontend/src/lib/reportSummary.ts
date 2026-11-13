import { tamperResistancePct, type TamperIssue } from './tamperDisplay'

export interface VulnRow {
    file: string
    line: number
    type: string
    severity: string
    code: string
}

export interface ProcEvRow {
    file: string
    line: number
    type: string
    function: string
    risk: string
    tainted: boolean
}

export interface MalRow {
    file: string
    line: number
    type: string
    severity: string
    evidence: string
}

export interface ScanReportPayload {
    id: number
    project_path: string
    scan_mode: string
    file_count: number
    total_size_kb: number
    risk_score: number | null
    risk_level: string | null
    created_at: string | null
    vulnerabilities: VulnRow[]
    process_events: ProcEvRow[]
    taint_paths?: {
        source: string
        sink: string
        file: string
        line: number
        severity: string
        confidence?: string
        sanitized?: boolean
        category?: string
        count?: number
    }[]
    malicious_indicators: MalRow[]
    process_graph: { nodes: string[]; edges: { from: string; to: string; file?: string | null }[] }
    tamperability: TamperIssue[]
}

export function formatReportId(scanId: number, createdAt: string | null): string {
    const d = createdAt ? new Date(createdAt) : new Date()
    const y = d.getFullYear()
    const m = String(d.getMonth() + 1).padStart(2, '0')
    const day = String(d.getDate()).padStart(2, '0')
    return `SCAN-${y}${m}${day}-${String(scanId).padStart(3, '0')}`
}

export function fmtLongDate(iso: string | null): string {
    if (!iso) return '—'
    try {
        return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'long' })
    } catch {
        return iso
    }
}

export function countVulnSeverity(vulns: VulnRow[]) {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    for (const v of vulns) {
        const s = v.severity as keyof typeof c
        if (s in c) c[s]++
    }
    return c
}

function tamperScoreSum(t: TamperIssue[]) {
    return Math.min(100, (t || []).reduce((s, x) => s + (x.score || 0), 0))
}

export function combinedDimensionScores(scan: ScanReportPayload) {
    const riskScore = scan.risk_score ?? 0
    const vn = scan.vulnerabilities?.length ?? 0
    const crit = (scan.vulnerabilities || []).filter(x => x.severity === 'Critical' || x.severity === 'High').length
    const codeQuality = Math.max(5, Math.min(100, 100 - vn * 4 - crit * 6))
    const tainted = (scan.process_events || []).filter(e => e.tainted).length
    const pe = (scan.process_events || []).length
    const processSafety = Math.max(5, Math.min(100, 100 - tainted * 10 - pe * 2))
    const ts = tamperScoreSum(scan.tamperability || [])
    const configSecurity = Math.max(5, Math.min(100, 100 - Math.min(ts, 80)))
    const malCount = scan.malicious_indicators?.length ?? 0
    const maliciousPatterns = Math.max(0, Math.min(100, 100 - malCount * 14))
    const tamperPct = tamperResistancePct(scan.tamperability || [])
    const overall = Math.round(
        (codeQuality + processSafety + configSecurity + maliciousPatterns + tamperPct) / 5,
    )
    return {
        overall,
        codeQuality: Math.round(codeQuality),
        processSafety: Math.round(processSafety),
        configSecurity: Math.round(configSecurity),
        maliciousPatterns: Math.round(maliciousPatterns),
        tamperability: tamperPct,
        riskScore,
        riskLevel: scan.risk_level ?? 'Unknown',
    }
}

export function buildExecutiveSummary(scan: ScanReportPayload): string {
    const date = fmtLongDate(scan.created_at)
    const n = scan.vulnerabilities.length
    const rs = scan.risk_score ?? 0
    const rl = scan.risk_level ?? 'Unknown'
    const crit = countVulnSeverity(scan.vulnerabilities).Critical
    return `A full behavioral security analysis was performed on ${date}. The overall risk score is ${rs}/100 (${rl} Risk). The scan identified ${n} vulnerability finding${n === 1 ? '' : 's'} across ${scan.file_count} scanned file${scan.file_count === 1 ? '' : 's'}${crit > 0 ? `, including ${crit} critical-severity item${crit === 1 ? '' : 's'}` : ''}. This report summarizes findings across vulnerabilities, process behavior, malicious patterns, tamperability, and combined posture.`
}

export function buildVulnSection(scan: ScanReportPayload): string {
    const c = countVulnSeverity(scan.vulnerabilities)
    const vulns = scan.vulnerabilities
    if (vulns.length === 0) return 'No vulnerability findings were recorded for this scan.'

    const bySev = (sev: string) => vulns.filter(v => v.severity === sev).map(v => v.type)
    const uniq = (arr: string[]) => [...new Set(arr)]

    const parts: string[] = []
    if (c.Critical > 0) parts.push(`${c.Critical} Critical: ${uniq(bySev('Critical')).join(', ')}.`)
    if (c.High > 0) parts.push(`${c.High} High: ${uniq(bySev('High')).join(', ')}.`)
    if (c.Medium > 0) parts.push(`${c.Medium} Medium: ${uniq(bySev('Medium')).join(', ')}.`)
    if (c.Low > 0) parts.push(`${c.Low} Low: ${uniq(bySev('Low')).join(', ')}.`)

    const topFiles = [...new Set(vulns.map(v => v.file.replace(/\\/g, '/').split('/').pop() || v.file))].slice(0, 4)
    return `Breakdown of ${vulns.length} total findings: ${parts.join(' ')} Severe issues are concentrated in ${topFiles.join(', ')}.`
}

export function buildProcessSection(scan: ScanReportPayload): string {
    const pe = scan.process_events?.length ?? 0
    const pg = scan.process_graph
    const nodes = pg?.nodes?.length ?? 0
    const edges = pg?.edges?.length ?? 0
    const tainted = (scan.process_events || []).filter(e => e.tainted)
    const taintPaths = scan.taint_paths || []
    const highConfPaths = taintPaths.filter(p => (p.confidence || '').toLowerCase() === 'high')
    if (pe === 0 && nodes === 0 && edges === 0) {
        return 'No process-flow events or graph edges were produced. Run analysis on Python projects with subprocess, taint, or network patterns to populate this section.'
    }
    const taintHint =
        tainted.length > 0
            ? ` ${tainted.length} event(s) involve tainted data reaching sinks (e.g. ${tainted[0].function} in ${tainted[0].file.replace(/\\/g, '/').split('/').pop()}).`
            : ''
    const pathHint = taintPaths.length
        ? ` ${taintPaths.length} grouped source-to-sink taint path(s) were derived, with ${highConfPaths.length} high-confidence path(s).`
        : ''
    return `The analyzer recorded ${pe} process risk event${pe === 1 ? '' : 's'} and a process graph with ${nodes} node${nodes === 1 ? '' : 's'} and ${edges} edge${edges === 1 ? '' : 's'}.${taintHint}${pathHint} Review the Process Graph view for the full execution path.`
}

export function buildMaliciousSection(scan: ScanReportPayload): string {
    const m = scan.malicious_indicators || []
    if (m.length === 0) return 'No malicious behavior indicators were raised for this scan.'
    const lines = m.slice(0, 5).map(
        x =>
            `${x.type} at ${x.file.replace(/\\/g, '/').split('/').pop()}:${x.line} (${x.severity})`,
    )
    return `${m.length} malicious indicator${m.length === 1 ? '' : 's'} confirmed. Highlights: ${lines.join('; ')}${m.length > 5 ? ' …' : ''}`
}

export function buildTamperSection(scan: ScanReportPayload): string {
    const t = scan.tamperability || []
    const pct = tamperResistancePct(t)
    const label = pct >= 70 ? 'High' : pct >= 45 ? 'Medium' : 'Low'
    if (t.length === 0)
        return `Tamper resistance is estimated at ${pct}% (${label}) based on aggregate burden. No tamper-specific issues were logged.`
    const types = [...new Set(t.map(x => x.type))]
    return `Tamper resistance score: ${pct}% (${label} resistance). ${t.length} tamperability indicator${t.length === 1 ? '' : 's'} across categories: ${types.slice(0, 5).join(', ')}${types.length > 5 ? ' …' : ''}.`
}

export function buildFinalSection(dims: ReturnType<typeof combinedDimensionScores>): string {
    return `Overall combined security score: ${dims.overall}/100 (${dims.overall < 40 ? 'Needs Immediate Attention' : dims.overall < 65 ? 'Elevated Risk' : 'Within Acceptable Range'}). Breakdown — Code Quality: ${dims.codeQuality}/100; Process Safety: ${dims.processSafety}/100; Config Security: ${dims.configSecurity}/100; Malicious Patterns: ${dims.maliciousPatterns}/100; Tamperability: ${dims.tamperability}/100.`
}

export function recommendedActions(scan: ScanReportPayload): string[] {
    const out: string[] = []
    const vulns = scan.vulnerabilities || []
    const crit = vulns.filter(v => v.severity === 'Critical' || v.severity === 'High')
    if (crit.some(v => v.type.toLowerCase().includes('sql'))) out.push('Remediate SQL injection and unsafe query construction')
    if (crit.some(v => v.type.toLowerCase().includes('command') || v.type.toLowerCase().includes('injection')))
        out.push('Remove user-controlled input from system commands')
    if ((scan.malicious_indicators || []).some(m => m.type.toLowerCase().includes('shell')))
        out.push('Remove reverse-shell or execution chains')
    if ((scan.tamperability || []).some(t => t.type.toLowerCase().includes('debug')))
        out.push('Disable debug mode in production deployments')
    if ((scan.tamperability || []).some(t => t.type.toLowerCase().includes('exposed')))
        out.push('Protect or relocate exposed configuration files')
    if (crit.some(v => v.type.toLowerCase().includes('secret'))) out.push('Rotate credentials and remove hardcoded secrets')
    if (out.length < 3 && vulns.length) out.push('Review prioritized findings in the Vulnerabilities view')
    return out.slice(0, 6)
}

export function buildReportHtml(scan: ScanReportPayload, dims: ReturnType<typeof combinedDimensionScores>): string {
    const esc = (s: string) =>
        s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    const sections = [
        ['Executive Summary', buildExecutiveSummary(scan)],
        ['Vulnerabilities Summary', buildVulnSection(scan)],
        ['Process Behavior Report', buildProcessSection(scan)],
        ['Malicious Pattern Summary', buildMaliciousSection(scan)],
        ['Tamperability Summary', buildTamperSection(scan)],
        ['Final Combined Security Score', buildFinalSection(dims) + ' Recommended: ' + recommendedActions(scan).join('; ')],
    ]
    const body = sections
        .map(
            ([h, p]) =>
                `<section><h2>${esc(h as string)}</h2><p>${esc(p as string)}</p></section>`,
        )
        .join('\n')
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Report ${scan.id}</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;color:#111}h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.5rem}p{line-height:1.5;color:#333}</style></head><body>
<h1>Security Report — ${esc(formatReportId(scan.id, scan.created_at))}</h1>
<p style="color:#555">Project: ${esc(scan.project_path)}</p>
${body}
</body></html>`
}
