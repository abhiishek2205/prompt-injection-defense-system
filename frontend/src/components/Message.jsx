import { AlertIcon, CheckIcon, RewriteIcon, StopIcon } from './icons'

// What each layer's status means, in words a judge can read without the code.
const STAGES = [
    { key: 'sanitize', label: 'Sanitize', words: { pass: 'Cleaned', warn: 'Cleaned', fail: 'Rejected', skip: 'Skipped' } },
    { key: 'detect', label: 'Detect', words: { pass: 'No attack', warn: 'Suspicious', fail: 'Attack found', skip: 'Skipped' } },
    { key: 'reprompt', label: 'Reprompt', words: { pass: 'Not needed', warn: 'Attack removed', fail: 'Blocked', skip: 'Not needed' } },
    { key: 'contain', label: 'Contain', words: { pass: 'No leak', warn: 'Leak redacted', fail: 'Leak', skip: 'Not reached' } },
]

const TONE = { pass: 'ok', warn: 'warn', fail: 'stop', skip: 'idle' }

const METHODS = {
    local_pattern: 'pattern rules',
    groq_local_pattern: 'pattern rules',
    attack_memory: 'attack memory',
    ml_classifier: 'the ML classifier',
    multi_turn: 'the multi-turn check',
    groq_llm: 'the LLM judge (Groq)',
    gemini_llm: 'the LLM judge (Gemini)',
}

const pct = (x) => Math.round((x || 0) * 100)

// ─── Defence trace ──────────────────────────────────────────────────────────
// The four layers as one track. The layer that stopped the message is marked;
// layers it never reached fade out. Memory and ML sit underneath: memory can
// block, ML is advisory and drawn dashed.
export function DefenceTrace({ pipeline, security }) {
    if (!pipeline) return null
    const stopAt = STAGES.findIndex(s => pipeline[s.key] === 'fail' && s.key !== 'detect')
    const memory = security?.memory_opinion
    const ml = security?.ml_opinion

    return (
        <div className="trace">
            <ol className="trace__track" aria-label="Defence layers">
                {STAGES.map((s, i) => {
                    const status = pipeline[s.key] || 'skip'
                    const unreached = stopAt !== -1 && i > stopAt
                    const tone = unreached ? 'off' : TONE[status]
                    return (
                        <li key={s.key} className={`trace__stage trace__stage--${tone}`}
                            style={{ '--i': i }}>
                            <span className="trace__node">
                                {tone === 'ok' && <CheckIcon size={12} />}
                                {tone === 'stop' && <StopIcon size={12} />}
                                {tone === 'warn' && <RewriteIcon size={11} />}
                            </span>
                            <span className="trace__label">{s.label}</span>
                            <span className="trace__word">{unreached ? 'Not reached' : s.words[status]}</span>
                        </li>
                    )
                })}
            </ol>
            {(memory?.available || ml?.available) && (
                <div className="trace__extra">
                    {memory?.available && (
                        <span className={`gauge ${memory.is_malicious ? 'gauge--stop' : ''}`}
                            title={`Attack memory: ${pct(memory.confidence)}% similar to a known attack`
                                + (memory.matched_source ? ` (${memory.matched_source})` : '')
                                + `. Blocks at ${pct(memory.threshold)}%.`}>
                            <span className="gauge__name">Memory</span>
                            <span className="gauge__bar"><span style={{ width: `${pct(memory.confidence)}%` }} /></span>
                            <span className="gauge__value">
                                {pct(memory.confidence)}% similar{memory.is_malicious ? ', known attack' : ''}
                            </span>
                        </span>
                    )}
                    {ml?.available && (
                        <span className={`gauge gauge--advisory ${ml.is_malicious ? 'gauge--warn' : ''}`}
                            title={`ML classifier (advisory): ${pct(ml.confidence)}% attack probability, `
                                + `flags at ${pct(ml.threshold)}%. Recorded for comparison; it does not block.`}>
                            <span className="gauge__name">ML</span>
                            <span className="gauge__bar"><span style={{ width: `${pct(ml.confidence)}%` }} /></span>
                            <span className="gauge__value">
                                {pct(ml.confidence)}%{ml.is_malicious ? ', would flag' : ''}
                            </span>
                        </span>
                    )}
                </div>
            )}
        </div>
    )
}

// ─── Verdict line ───────────────────────────────────────────────────────────
function Verdict({ kind, children }) {
    const Icon = { blocked: StopIcon, rewritten: RewriteIcon, passed: CheckIcon, open: AlertIcon }[kind]
    return (
        <div className="verdict">
            <span className={`verdict__badge verdict__badge--${kind}`}>
                <Icon size={13} />
                {{ blocked: 'Blocked', rewritten: 'Rewritten', passed: 'Passed', open: 'Unprotected' }[kind]}
            </span>
            {children && <span className="verdict__how">{children}</span>}
        </div>
    )
}

function methodText(security) {
    const m = METHODS[security?.detection_method]
    return m ? `by ${m}` : null
}

// ─── Assistant reply ────────────────────────────────────────────────────────
export function Reply({ msg }) {
    const t = msg.type || 'safe'
    const leak = msg.pipeline?.contain === 'warn'

    if (t === 'blocked') {
        return (
            <article className="reply">
                <Verdict kind="blocked">
                    {methodText(msg.security)}
                    {msg.security?.confidence != null && <span className="verdict__conf">{pct(msg.security.confidence)}% confident</span>}
                </Verdict>
                <p className="reply__reason">{msg.security?.reason || 'Stopped by the defence pipeline.'}</p>
                <p className="reply__note">NexusCore never saw this message.</p>
                <DefenceTrace pipeline={msg.pipeline} security={msg.security} />
            </article>
        )
    }

    if (t === 'reprompted') {
        return (
            <article className="reply">
                <Verdict kind="rewritten">{methodText(msg.security)}</Verdict>
                {msg.reprompted_query && (
                    <div className="reply__rewrite">
                        <span className="reply__rewrite-label">NexusCore received</span>
                        <code>{msg.reprompted_query}</code>
                    </div>
                )}
                {msg.explanation && <p className="reply__note">{msg.explanation}</p>}
                <div className="reply__body">{msg.content}</div>
                <DefenceTrace pipeline={msg.pipeline} security={msg.security} />
            </article>
        )
    }

    if (t === 'unshielded') {
        return (
            <article className="reply reply--open">
                <Verdict kind="open">Shield off, no layer checked this message</Verdict>
                <div className="reply__body">{msg.content}</div>
            </article>
        )
    }

    if (msg.error) {
        return (
            <article className="reply reply--error">
                <p className="reply__reason">{msg.content}</p>
            </article>
        )
    }

    return (
        <article className="reply">
            <Verdict kind="passed">{leak ? 'with a leak redacted from the answer' : null}</Verdict>
            <div className="reply__body">{msg.content}</div>
            <DefenceTrace pipeline={msg.pipeline} security={msg.security} />
        </article>
    )
}

// ─── Side by side: the same message with and without PromptShield ───────────
export function Comparison({ msg }) {
    return (
        <div className="compare">
            <div className="compare__col">
                <h3 className="compare__title">With PromptShield</h3>
                <Reply msg={msg} />
            </div>
            <div className="compare__col">
                <h3 className="compare__title compare__title--open">Without protection</h3>
                <article className="reply reply--open">
                    <div className="reply__body">{msg.unshielded_content || 'No response.'}</div>
                </article>
            </div>
        </div>
    )
}

export function Checking() {
    return (
        <div className="checking" role="status">
            <span className="checking__dots"><i /><i /><i /></span>
            Checking the message
        </div>
    )
}
