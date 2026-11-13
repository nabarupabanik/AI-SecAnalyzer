import { useEffect, useState } from 'react'

const KEY = 'sast-high-contrast'

export default function HighContrastToggle() {
    const [on, setOn] = useState(() =>
        typeof localStorage !== 'undefined' && localStorage.getItem(KEY) === '1',
    )

    useEffect(() => {
        document.documentElement.classList.toggle('high-contrast', on)
        try {
            localStorage.setItem(KEY, on ? '1' : '0')
        } catch {
            /* ignore */
        }
    }, [on])

    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 10,
                paddingTop: 16,
                marginTop: 16,
                borderTop: '1px solid var(--border)',
            }}
        >
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>High contrast</span>
            <button
                type="button"
                role="switch"
                aria-checked={on}
                aria-label="High contrast mode"
                className={`toggle-track ${on ? 'on' : ''}`}
                onClick={() => setOn(o => !o)}
            >
                <div className="toggle-thumb" />
            </button>
        </div>
    )
}
