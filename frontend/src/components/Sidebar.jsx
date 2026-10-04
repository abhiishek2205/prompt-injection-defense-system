import { useState } from 'react'
import { PRESET_SECTIONS, TOTAL_PRESETS } from '../presets'
import { ChevronIcon, CloseIcon, PlusIcon, ShieldMark } from './icons'

function memoryValue(memory) {
    if (!memory?.available) return null
    const size = memory.size.toLocaleString('en-US')
    return memory.learned ? `${size} (+${memory.learned} learned)` : size
}

function memoryTitle(memory) {
    return `${memory.seed} known attacks from the training data, ${memory.learned} learned at runtime `
        + `from canary leaks and LLM blocks. ${memory.hits} matched this session; `
        + `blocks at ${Math.round(memory.threshold * 100)}% similarity.`
}

function shadowTitle(s) {
    return `ML classifier, ${s.can_block ? 'blocking' : 'advisory'}: flagged ${s.flagged} of ${s.scored} messages.\n`
        + `+${s.would_add}: flagged, but the pipeline let it through.\n`
        + `−${s.missed}: caught by the pipeline, not flagged by ML.\n`
        + `On labelled test prompts: ${s.false_positives} false positives, ${s.false_negatives} false negatives.`
}

function Session({ metrics }) {
    const counts = [
        { label: 'Blocked', value: metrics.blocked, tone: 'stop' },
        { label: 'Rewritten', value: metrics.reprompted, tone: 'warn' },
        { label: 'Passed', value: Math.max(0, metrics.safe - metrics.reprompted), tone: 'ok' },
        { label: 'Redacted', value: metrics.contained, tone: 'warn',
          title: 'Answers where containment removed leaked secrets' },
    ]
    const shadow = metrics.ml_shadow
    const rows = [
        { label: 'Average check time', value: `${Math.round(metrics.avg_latency)} ms` },
        metrics.attack_memory?.available && {
            label: 'Known attacks', value: memoryValue(metrics.attack_memory), title: memoryTitle(metrics.attack_memory),
        },
        shadow?.scored > 0 && {
            label: 'ML would add / missed', value: `+${shadow.would_add} / −${shadow.missed}`, title: shadowTitle(shadow),
        },
        { label: 'Test-set mistakes', value: `${metrics.false_positives} FP, ${metrics.false_negatives} FN`,
          title: 'Messages from the test set with a known answer that the pipeline got wrong: '
              + 'harmless ones blocked (FP) and attacks let through (FN).' },
    ].filter(Boolean)

    return (
        <section className="session" aria-labelledby="session-title">
            <h2 id="session-title" className="side__heading">This session</h2>
            <dl className="session__counts">
                {counts.map(c => (
                    <div key={c.label} className={`session__count session__count--${c.tone}`} title={c.title}>
                        <dt>{c.label}</dt>
                        <dd>{c.value}</dd>
                    </div>
                ))}
            </dl>
            <dl className="session__rows">
                {rows.map(r => (
                    <div key={r.label} className="session__row" title={r.title}>
                        <dt>{r.label}</dt>
                        <dd>{r.value}</dd>
                    </div>
                ))}
            </dl>
        </section>
    )
}

export default function Sidebar({ metrics, onNewChat, onPick, open, onClose }) {
    const [expanded, setExpanded] = useState('inject')

    return (
        <aside className={`side ${open ? 'side--open' : ''}`} aria-label="PromptShield">
            <div className="side__top">
                <div className="brand">
                    <span className="brand__mark"><ShieldMark /></span>
                    <span className="brand__name">PromptShield</span>
                    <button className="icon-btn side__close" onClick={onClose} aria-label="Close menu">
                        <CloseIcon />
                    </button>
                </div>
                <button id="new-chat-btn" className="btn btn--outline btn--block" onClick={onNewChat}>
                    <PlusIcon size={16} /> New chat
                </button>
            </div>

            <nav className="side__scroll" aria-labelledby="library-title">
                <div className="side__heading-row">
                    <h2 id="library-title" className="side__heading">Attack library</h2>
                    <span className="side__count">{TOTAL_PRESETS} prompts</span>
                </div>
                <p className="side__hint">Pick one to load it into the message box.</p>

                {PRESET_SECTIONS.map(section => (
                    <div key={section.id} className="lib">
                        <div className="lib__section">
                            <span className={`lib__marker lib__marker--${section.expect}`} aria-hidden="true" />
                            <span className="lib__section-name">{section.label}</span>
                            <span className="lib__expect">{section.hint}</span>
                        </div>
                        {section.groups.map(group => {
                            const isOpen = expanded === group.id
                            return (
                                <div key={group.id} className="lib__group">
                                    <button className="lib__group-btn" aria-expanded={isOpen}
                                        onClick={() => setExpanded(isOpen ? null : group.id)}>
                                        <ChevronIcon size={14} className="lib__chev" />
                                        <span>{group.label}</span>
                                        <span className="lib__n">{group.prompts.length}</span>
                                    </button>
                                    {isOpen && (
                                        <ul className="lib__list">
                                            {group.prompts.map(p => (
                                                <li key={p.label}>
                                                    <button className="lib__item" title={p.prompt}
                                                        onClick={() => onPick(p.prompt)}>
                                                        {p.label}
                                                    </button>
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                ))}
            </nav>

            <Session metrics={metrics} />
            <footer className="side__foot">Team SRON, Echelon Hackathon</footer>
        </aside>
    )
}
