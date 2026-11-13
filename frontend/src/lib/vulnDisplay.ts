/** Derive display category from backend vulnerability `type` string (not stored in DB). */
export function deriveCategory(type: string): string {
    const t = (type || '').toLowerCase()
    if (
        t.includes('sql') ||
        t.includes('injection') ||
        t.includes('command') ||
        t.includes('xss') ||
        t.includes('path') ||
        t.includes('traversal') ||
        t.includes('deserialize') ||
        t.includes('unvalidated')
    )
        return 'Injection'
    if (t.includes('secret') || t.includes('config') || t.includes('hardcoded') || t.includes('env'))
        return 'Config Weakness'
    if (t.includes('auth') || t.includes('access') || t.includes('permission') || t.includes('missing'))
        return 'Access Control'
    if (t.includes('crypto') || t.includes('cipher') || t.includes('hash') || t.includes('weak'))
        return 'Cryptography'
    if (t.includes('shell') || t.includes('malicious') || t.includes('reverse') || t.includes('c2'))
        return 'Malicious Behavior'
    return 'Other'
}

function severityBase(severity: string): number {
    const s = (severity || '').toLowerCase()
    if (s === 'critical') return 94
    if (s === 'high') return 78
    if (s === 'medium') return 56
    if (s === 'low') return 32
    return 50
}

/** Stable 5–99 risk score from severity + finding identity (matches dashboard-style numeric risk). */
export function deriveRiskScore(severity: string, type: string, file: string, line: number): number {
    const base = severityBase(severity)
    const jitter = (file.length + line * 3 + type.length * 2) % 11
    return Math.min(99, Math.max(5, base + jitter - 5))
}

export function severityStyle(severity: string): { bg: string; border: string; color: string; riskColor: string } {
    const s = (severity || '').toLowerCase()
    if (s === 'critical')
        return {
            bg: 'rgba(255,69,58,0.15)',
            border: 'rgba(255,69,58,0.55)',
            color: '#FF453A',
            riskColor: '#FF453A',
        }
    if (s === 'high')
        return {
            bg: 'rgba(255,159,10,0.12)',
            border: 'rgba(255,159,10,0.5)',
            color: '#FF9F0A',
            riskColor: '#FF9F0A',
        }
    if (s === 'medium')
        return {
            bg: 'rgba(255,214,10,0.1)',
            border: 'rgba(255,214,10,0.45)',
            color: '#FFD60A',
            riskColor: '#FFD60A',
        }
    if (s === 'low')
        return {
            bg: 'rgba(10,132,255,0.12)',
            border: 'rgba(10,132,255,0.45)',
            color: '#0A84FF',
            riskColor: '#0A84FF',
        }
    return {
        bg: 'rgba(245,245,247,0.08)',
        border: 'rgba(245,245,247,0.2)',
        color: 'rgba(245,245,247,0.75)',
        riskColor: 'rgba(245,245,247,0.75)',
    }
}
