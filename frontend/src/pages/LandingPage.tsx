import { useNavigate } from 'react-router-dom'
import { Shield, Zap, GitBranch, Lock, ChevronRight, FileSearch, Gauge } from 'lucide-react'

/* ── Floating ambient particle ──────────────── */
function Particle({ x, y, size, duration, color }: {
    x: number; y: number; size: number; duration: number; color: string
}) {
    return (
        <div
            className="particle"
            style={{
                left: `${x}%`,
                top: `${y}%`,
                width: size,
                height: size,
                background: color,
                animationDuration: `${duration}s`,
                filter: 'blur(1px)',
            }}
        />
    )
}

/* ── Shield logo icon ───────────────────────── */
function LogoIcon() {
    return (
        <div style={{
            width: 72,
            height: 72,
            borderRadius: 20,
            background: 'linear-gradient(135deg, rgba(10,132,255,0.25) 0%, rgba(10,132,255,0.10) 100%)',
            border: '1px solid rgba(10,132,255,0.30)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative',
            boxShadow: '0 0 40px rgba(10,132,255,0.15), 0 8px 32px rgba(0,0,0,0.4)',
            backdropFilter: 'blur(12px)',
        }}>
            <Shield size={36} color="#0A84FF" strokeWidth={1.5} />
            {/* Neural dot */}
            <div style={{
                position: 'absolute',
                top: 12,
                right: 14,
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#FF453A',
                boxShadow: '0 0 8px rgba(255,69,58,0.8)',
            }} />
        </div>
    )
}

export default function LandingPage() {
    const navigate = useNavigate()

    return (
        <div
            className="ambient-bg dot-grid"
            style={{
                minHeight: '100vh',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                position: 'relative',
                overflow: 'hidden',
                padding: '32px 24px',
            }}
        >
            {/* Ambient particles */}
            <Particle x={8} y={22} size={6} duration={4.2} color="rgba(10,132,255,0.6)" />
            <Particle x={88} y={38} size={5} duration={5.8} color="rgba(45,212,191,0.5)" />
            <Particle x={15} y={72} size={4} duration={6.1} color="rgba(10,132,255,0.4)" />
            <Particle x={82} y={70} size={7} duration={4.7} color="rgba(255,159,10,0.5)" />
            <Particle x={50} y={88} size={4} duration={5.3} color="rgba(45,212,191,0.4)" />
            <Particle x={30} y={15} size={5} duration={7.0} color="rgba(255,69,58,0.3)" />

            {/* Content */}
            <div style={{ textAlign: 'center', maxWidth: 680, zIndex: 1 }}>

                {/* Logo */}
                <div className="fade-up fade-up-1" style={{ display: 'flex', justifyContent: 'center', marginBottom: 28 }}>
                    <LogoIcon />
                </div>

                {/* Badge */}
                <div className="fade-up fade-up-2" style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
                    <div style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 7,
                        padding: '6px 16px',
                        background: 'rgba(10,132,255,0.10)',
                        border: '1px solid rgba(10,132,255,0.20)',
                        borderRadius: 999,
                        fontSize: 11,
                        fontWeight: 600,
                        letterSpacing: '0.08em',
                        color: 'rgba(10,132,255,0.90)',
                        textTransform: 'uppercase',
                    }}>
                        <Zap size={11} />
                        Enterprise DevSecOps Platform
                    </div>
                </div>

                {/* Main title */}
                <div className="fade-up fade-up-2" style={{ marginBottom: 16 }}>
                    <h1 style={{
                        fontSize: 'clamp(36px, 6vw, 58px)',
                        fontWeight: 800,
                        lineHeight: 1.08,
                        letterSpacing: '-0.03em',
                        color: '#F5F5F7',
                    }}>
                        Application{' '}
                        <span style={{
                            background: 'linear-gradient(90deg, #0A84FF 0%, #2DD4BF 100%)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            backgroundClip: 'text',
                        }}>
                            Security & Risk
                        </span>{' '}
                        Analyzer
                    </h1>
                </div>

                {/* Subtitle */}
                <div className="fade-up fade-up-3" style={{ marginBottom: 48 }}>
                    <p style={{
                        fontSize: 17,
                        color: 'var(--text-secondary)',
                        fontWeight: 400,
                        lineHeight: 1.6,
                        letterSpacing: '-0.01em',
                    }}>
                        Static SAST, process-flow modeling, tamperability checks, and unified risk scoring
                    </p>
                </div>

                {/* CTA buttons */}
                <div className="fade-up fade-up-4" style={{
                    display: 'flex',
                    gap: 14,
                    justifyContent: 'center',
                    flexWrap: 'wrap',
                    marginBottom: 72,
                }}>
                    <button
                        className="btn-primary"
                        onClick={() => navigate('/scan')}
                        style={{ fontSize: 16, padding: '14px 32px' }}
                    >
                        <Shield size={18} />
                        Start New Scan
                    </button>
                    <button
                        className="btn-secondary"
                        onClick={() => navigate('/scan-history')}
                        style={{ fontSize: 16, padding: '14px 32px' }}
                    >
                        View Scan History
                        <ChevronRight size={16} style={{ marginLeft: 2 }} />
                    </button>
                </div>

                {/* Feature pills */}
                <div className="fade-up fade-up-5" style={{
                    display: 'flex',
                    gap: 10,
                    justifyContent: 'center',
                    flexWrap: 'wrap',
                }}>
                    <div className="feature-pill"><Lock size={13} /> Vulnerability Detection</div>
                    <div className="feature-pill"><FileSearch size={13} /> Static analysis (SAST)</div>
                    <div className="feature-pill"><Gauge size={13} /> Unified risk scoring</div>
                    <div className="feature-pill"><GitBranch size={13} /> Process flow mapping</div>
                </div>
            </div>

            {/* Help button */}
            <button
                type="button"
                aria-label="Help"
                className="btn-ghost"
                style={{
                    position: 'fixed',
                    bottom: 24,
                    right: 24,
                    width: 44,
                    height: 44,
                    borderRadius: '50%',
                    padding: 0,
                    justifyContent: 'center',
                    fontSize: 17,
                    fontWeight: 700,
                    color: 'var(--text-secondary)',
                    borderColor: 'var(--border)',
                    background: 'rgba(255,255,255,0.06)',
                }}
            >?</button>
        </div>
    )
}
