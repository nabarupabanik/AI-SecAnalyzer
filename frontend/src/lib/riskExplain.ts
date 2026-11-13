/**
 * Mirrors scanner/risk_scoring.py — same weights so copy matches stored overall_score.
 */

export interface VulnLike {
    severity: string
}

export interface ProcLike {
    risk: string
    tainted?: boolean
}

export interface MalLike {
    severity: string
}

export interface TamperLike {
    score?: number
}

export interface DependencyLike {
    dependency_name: string
    installed_version: string
    fixed_version: string | null
    vulnerability_id: string
    severity: string
    description: string
    references: string[]
    ecosystem: string
    file_path: string
}

function clampInt(x: number, lo = 0, hi = 100): number {
    return Math.max(lo, Math.min(hi, Math.round(x)))
}

export function computeStaticScore(vulns: VulnLike[]): number {
    const w: Record<string, number> = { Low: 5, Medium: 10, High: 20 }
    let s = 0
    for (const v of vulns || []) s += w[v.severity] ?? 5
    return clampInt(s)
}

export function computeProcessScore(events: ProcLike[]): number {
    const w: Record<string, number> = { Low: 5, Medium: 10, High: 20 }
    let s = 0
    for (const e of events || []) {
        s += w[e.risk] ?? 5
        if (e.tainted) s += 10
    }
    return clampInt(s)
}

export function computeMaliciousScore(rows: MalLike[]): number {
    const w: Record<string, number> = { Low: 10, Medium: 20, High: 30 }
    let s = 0
    for (const m of rows || []) s += w[m.severity] ?? 10
    return clampInt(s)
}

export function computeTamperScore(issues: TamperLike[]): number {
    const raw = (issues || []).reduce((a, x) => a + (x.score || 0), 0)
    return Math.max(0, Math.min(100, Math.round(raw)))
}

export function computeDependencyScore(dependencies: DependencyLike[]): number {
    const weights: Record<string, number> = { Low: 8, Medium: 15, High: 25, Critical: 35 }
    let score = 0
    
    for (const dep of dependencies || []) {
        const severityWeight = weights[dep.severity] || 15
        
        // 20% boost for critical ecosystems (npm, pip)
        const ecosystemMultiplier = ['npm', 'pip'].includes(dep.ecosystem) ? 1.2 : 1.0
        
        // 30% boost for unfixed vulnerabilities
        const fixMultiplier = !dep.fixed_version ? 1.3 : 1.0
        
        score += severityWeight * ecosystemMultiplier * fixMultiplier
    }
    
    return clampInt(score)
}

export function computeExploitChainScore(exploitChains: any[]): number {
    if (!exploitChains || exploitChains.length === 0) return 0
    
    let score = 0
    const weights: Record<string, number> = { confirmed: 35, probable: 20, theoretical: 10 }
    
    for (const chain of exploitChains) {
        const feasibility = (chain.feasibility as string) || 'theoretical'
        const weight = weights[feasibility] || weights.theoretical
        
        // Bonus for longer chains
        const lengthBonus = Math.min(((chain.chain_length as number) || 1) * 2, 10)
        
        // Bonus for confirmed chains
        const confirmedBonus = feasibility === 'confirmed' ? 15 : 0
        
        score += weight + lengthBonus + confirmedBonus
    }
    
    return clampInt(score)
}

export function computeOverallFromComponents(S: number, P: number, M: number, T: number, D: number, C: number): number {
    return clampInt(0.20 * S + 0.20 * P + 0.15 * M + 0.15 * T + 0.15 * D + 0.15 * C)
}

export interface RiskBreakdown {
    S: number
    P: number
    M: number
    T: number
    D: number
    C: number
    overall: number
    lines: string[]
}

export function explainRisk(v: {
    vulnerabilities: VulnLike[]
    process_events: ProcLike[]
    malicious_indicators: MalLike[]
    tamperability: TamperLike[]
    dependency_vulnerabilities?: DependencyLike[]
    exploit_chains?: any[]
    risk_score: number | null
}): RiskBreakdown {
    const S = computeStaticScore(v.vulnerabilities || [])
    const P = computeProcessScore(v.process_events || [])
    const M = computeMaliciousScore(v.malicious_indicators || [])
    const T = computeTamperScore(v.tamperability || [])
    const D = computeDependencyScore(v.dependency_vulnerabilities || [])
    const C = computeExploitChainScore(v.exploit_chains || [])
    const overall = computeOverallFromComponents(S, P, M, T, D, C)

    const wS = 0.20 * S
    const wP = 0.20 * P
    const wM = 0.15 * M
    const wT = 0.15 * T
    const wD = 0.15 * D
    const wC = 0.15 * C
    const parts = [
        { k: 'Static (findings)', v: wS },
        { k: 'Process / taint', v: wP },
        { k: 'Malicious patterns', v: wM },
        { k: 'Tamperability', v: wT },
        { k: 'Dependency vulnerabilities', v: wD },
        { k: 'Exploit chains', v: wC },
    ].sort((a, b) => b.v - a.v)

    const lines: string[] = [
        `Overall risk blends six layers: 20% static findings, 20% process/taint behavior, 15% malicious-pattern signals, 15% tamperability, 15% dependency vulnerabilities, and 15% exploit chains (patent-critical analysis).`,
        `Component scores (0-100 each): Static ${S}, Process ${P}, Malicious ${M}, Tamper ${T}, Dependencies ${D}, Exploit Chains ${C}.`,
        `Largest drivers here: ${parts[0].k} (~${parts[0].v.toFixed(1)} pts), then ${parts[1].k} (~${parts[1].v.toFixed(1)} pts).`,
    ]

    return { S, P, M, T, D, C, overall, lines }
}
