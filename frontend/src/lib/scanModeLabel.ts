/** Matches backend scan_mode values — labels for badges. */
export function scanModeLabel(mode: string): string {
    const m = (mode || '').toLowerCase()
    if (m === 'behavioral') return 'Behavioral Deep Scan'
    if (m === 'full') return 'Full Intelligence Scan'
    if (m === 'basic') return 'Basic Scan'
    return mode || 'Scan'
}
