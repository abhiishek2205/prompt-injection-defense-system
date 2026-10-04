import { MenuIcon, MoonIcon, SunIcon } from './icons'

const THREAT = {
    LOW: { label: 'Low', tone: 'ok' },
    GUARDED: { label: 'Guarded', tone: 'warn' },
    ELEVATED: { label: 'Elevated', tone: 'warn' },
    CRITICAL: { label: 'Critical', tone: 'stop' },
}

function Switch({ id, checked, onChange, label, children }) {
    return (
        <button id={id} type="button" role="switch" aria-checked={checked} aria-label={label}
            className="switch" onClick={() => onChange(!checked)}>
            <span className="switch__thumb">{children}</span>
        </button>
    )
}

export default function TopBar({ shieldOn, onShield, threatLevel, dark, onDark, onMenu }) {
    const threat = THREAT[threatLevel] || THREAT.LOW
    return (
        <header className="top">
            <button className="icon-btn top__menu" onClick={onMenu} aria-label="Open menu">
                <MenuIcon />
            </button>
            <div className="top__title">
                <h1>NexusCore<span className="top__long"> assistant</span></h1>
                <p>A fintech's internal assistant. Its instructions hold AWS keys, passwords and staff records.</p>
            </div>
            <div className="top__controls">
                <span className={`threat threat--${threat.tone}`}
                    title="Rises with each attack in this session and makes detection stricter">
                    <span className="threat__dot" aria-hidden="true" />
                    Threat level <strong>{threat.label}</strong>
                </span>
                <span className={`control ${shieldOn ? '' : 'control--off'}`}>
                    <label htmlFor="shield-switch">Shield</label>
                    <Switch id="shield-switch" checked={shieldOn} onChange={onShield} label="Shield" />
                </span>
                <Switch checked={dark} onChange={onDark} label="Dark mode">
                    {dark ? <MoonIcon size={12} /> : <SunIcon size={12} />}
                </Switch>
            </div>
        </header>
    )
}
