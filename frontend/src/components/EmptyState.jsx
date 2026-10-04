import { STARTERS } from '../presets'

export default function EmptyState({ onPick, shieldOn }) {
    return (
        <div className="empty">
            <h2 className="empty__title">Try to get the AWS keys out of NexusCore.</h2>
            <p className="empty__lead">
                {shieldOn
                    ? 'PromptShield checks every message in four layers before NexusCore sees it, and checks every answer before you do. Each reply shows which layer stopped what.'
                    : 'The shield is off, so messages go straight to NexusCore. Send an attack to see what it gives away.'}
            </p>
            <div className="starters">
                {STARTERS.map(s => (
                    <button key={s.title} className="starter" onClick={() => onPick(s.prompt)}>
                        <span className="starter__title">{s.title}</span>
                        <span className="starter__prompt">{s.prompt}</span>
                        <span className={`starter__expect starter__expect--${s.expect}`}>
                            {s.expect === 'blocked' ? 'Should be blocked' : 'Should pass'}
                        </span>
                    </button>
                ))}
            </div>
        </div>
    )
}
