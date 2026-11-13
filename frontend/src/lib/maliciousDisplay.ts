/** Category line for malicious indicator `type` (not stored in DB). */
export function maliciousCategory(type: string): string {
    const t = (type || '').toLowerCase()
    if (t.includes('reverse') || t.includes('shell')) return 'Remote Code Execution / C2 Callback'
    if (t.includes('base64') || (t.includes('exec') && t.includes('decode'))) return 'Code Obfuscation / Dynamic Code Execution'
    if (t.includes('exec') || t.includes('eval')) return 'Dynamic Code Execution'
    if (t.includes('ip') || t.includes('network') || t.includes('connect') || t.includes('socket'))
        return 'Command & Control / Data Exfiltration'
    if (t.includes('obfuscat')) return 'Anti-Analysis / Evasion Technique'
    if (t.includes('pattern') && t.includes('correlation')) return 'Multi-Vector Threat Pattern'
    if (t.includes('command injection') || t.includes('user input')) return 'Injection / Privilege Abuse'
    return 'Malicious Behavior'
}

function severityBase(severity: string): number {
    const s = (severity || '').toLowerCase()
    if (s === 'critical') return 96
    if (s === 'high') return 82
    if (s === 'medium') return 58
    if (s === 'low') return 35
    return 55
}

/** Numeric risk score for display (5–99). */
export function maliciousRiskScore(severity: string, type: string, file: string, line: number): number {
    const base = severityBase(severity)
    const jitter = (file.length + line * 2 + type.length) % 9
    return Math.min(99, Math.max(12, base + jitter - 4))
}

export function severityAccent(severity: string): {
    tagBg: string
    tagColor: string
    riskColor: string
    iconBg: string
} {
    const s = (severity || '').toLowerCase()
    if (s === 'critical')
        return {
            tagBg: 'rgba(255,69,58,0.25)',
            tagColor: '#FF453A',
            riskColor: '#FF453A',
            iconBg: 'rgba(80,25,28,0.95)',
        }
    if (s === 'high')
        return {
            tagBg: 'rgba(255,159,10,0.22)',
            tagColor: '#FF9F0A',
            riskColor: '#FF9F0A',
            iconBg: 'rgba(60,45,20,0.95)',
        }
    if (s === 'medium')
        return {
            tagBg: 'rgba(255,214,10,0.15)',
            tagColor: '#FFD60A',
            riskColor: '#FFD60A',
            iconBg: 'rgba(55,50,25,0.95)',
        }
    return {
        tagBg: 'rgba(10,132,255,0.15)',
        tagColor: '#0A84FF',
        riskColor: '#0A84FF',
        iconBg: 'rgba(20,35,55,0.95)',
    }
}
