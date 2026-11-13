import { Link, useNavigate } from 'react-router-dom'
import {
    ArrowLeft, FileStack, ShieldAlert, GitBranch, Biohazard, Settings2,
    LayoutDashboard, History, Network, DollarSign, Bot,
} from 'lucide-react'
import HighContrastToggle from './HighContrastToggle'

export type DashboardNavId =
    | 'dashboard'
    | 'security-debt'
    | 'dual-ai-remediation'
    | 'vulnerabilities'
    | 'process-graph'
    | 'malicious'
    | 'tamperability'
    | 'reports'
    | 'exploit-graph'
    | 'scan-history'
    | 'telemetry'

const NAV: { id: DashboardNavId; label: string; icon: typeof LayoutDashboard }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'security-debt', label: 'Security Debt & ROI', icon: DollarSign },
    { id: 'dual-ai-remediation', label: 'Dual-AI Remediation', icon: Bot },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'process-graph', label: 'Process Graph', icon: GitBranch },
    { id: 'malicious', label: 'Malicious Analysis', icon: Biohazard },
    { id: 'tamperability', label: 'Tamperability', icon: Settings2 },
    { id: 'reports', label: 'Reports', icon: FileStack },
    { id: 'exploit-graph', label: 'Exploit Graph', icon: Network },
    { id: 'scan-history', label: 'Scan History', icon: History },
]

type Props = {
    scanId: string
    active: DashboardNavId
    /** When true, analysis links go to /scan (no scan selected). */
    noScanContext?: boolean
}

export default function DashboardSidebar({ scanId, active, noScanContext }: Props) {
    const navigate = useNavigate()
    const base = `/dashboard/${scanId}`

    function hrefFor(item: (typeof NAV)[0]): string {
        if (item.id === 'scan-history') return '/scan-history'
        if (noScanContext) return '/scan'
        if (item.id === 'security-debt') return `${base}/security-debt`
        if (item.id === 'dual-ai-remediation') return `${base}/dual-ai-remediation`
        if (item.id === 'vulnerabilities') return `${base}/vulnerabilities`
        if (item.id === 'process-graph') return `${base}/process-graph`
        if (item.id === 'malicious') return `${base}/malicious`
        if (item.id === 'tamperability') return `${base}/tamperability`
        if (item.id === 'reports') return `${base}/reports`
        if (item.id === 'exploit-graph') return `${base}/exploit-graph`
        return base
    }

    return (
        <aside style={{
            width: 260,
            flexShrink: 0,
            borderRight: '1px solid var(--border-strong)',
            background: 'var(--bg-card)',
            display: 'flex',
            flexDirection: 'column',
            padding: '24px 16px',
        }}>
            <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1.2, color: 'var(--text-primary)' }}>
                AI SecAnalyzer
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', fontWeight: 600, marginTop: 2 }}>
                v2.4.1
            </div>

            <div className="section-label" style={{ marginTop: 28, marginBottom: 10 }}>
                ANALYSIS
            </div>

            <nav style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {NAV.map(item => {
                    const Icon = item.icon
                    const isActive = active === item.id
                    const to = hrefFor(item)
                    return (
                        <Link
                            key={item.id}
                            to={to}
                            className={`sidebar-nav-link${isActive ? ' sidebar-nav-link--active' : ''}`}
                        >
                            <Icon size={18} strokeWidth={isActive ? 2.1 : 1.75} /> {item.label}
                        </Link>
                    )
                })}
            </nav>

            <div style={{ marginTop: 'auto', paddingTop: 24 }}>
                <HighContrastToggle />
                <button type="button" className="btn-ghost" onClick={() => navigate('/')} style={{ width: '100%', justifyContent: 'flex-start' }}>
                    <ArrowLeft size={16} /> Back to Home
                </button>
            </div>
        </aside>
    )
}
