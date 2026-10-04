import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { PRESET_SECTIONS } from '../presets'
import { detectorName } from '../labels'
import { CheckIcon, StopIcon, RewriteIcon } from './icons'

// Two at a time: quick enough for a judge to watch, gentle on free-tier LLM
// rate limits (each harmless prompt costs a guardrail call and an answer).
const CONCURRENCY = 2

const PROMPTS = PRESET_SECTIONS.flatMap(section => section.groups.flatMap(group =>
    group.prompts.map(p => ({ ...p, group: group.label, expect: section.expect }))))

const VERDICT = { blocked: 'blocked', reprompted: 'rewritten', safe: 'passed' }

function freshRows() {
    return PROMPTS.map((p, id) => ({ ...p, id, status: 'waiting' }))
}

function judge(row, data) {
    const verdict = VERDICT[data.type] || 'passed'
    const stopped = verdict !== 'passed'
    return {
        ...row,
        status: 'done',
        verdict,
        // An attack counts as caught if it was blocked or rewritten; a
        // harmless prompt only counts if it passed untouched.
        correct: row.expect === 'blocked' ? stopped : !stopped,
        caughtBy: stopped ? detectorName(data.security?.detection_method) : null,
        ms: data.metrics?.avg_latency ?? null,
    }
}

// Runs every library prompt through POST /evaluate: the shielded pipeline in
// a throwaway session, so each prompt is judged on its own and the visitor's
// own threat score and counters stay as they were.
export function useScorecard(api, useGroq) {
    const [rows, setRows] = useState(null)
    const [running, setRunning] = useState(false)
    const [learned, setLearned] = useState(0)
    const runRef = useRef(0)

    const start = useCallback(async () => {
        const run = ++runRef.current
        const queue = freshRows()
        setRows(queue)
        setRunning(true)
        setLearned(0)
        // Attacks that get past detection but leak the canary are learned by
        // the attack memory as the run goes; count them to say so.
        const learnedCount = (d) => d?.attack_memory?.learned
        const before = await api('/metrics').then(r => r.json()).then(learnedCount).catch(() => undefined)
        let next = 0
        const update = (row) => {
            if (runRef.current === run) setRows(prev => prev.map(r => r.id === row.id ? row : r))
        }
        const worker = async () => {
            while (next < queue.length && runRef.current === run) {
                const row = queue[next++]
                update({ ...row, status: 'running' })
                try {
                    const res = await api('/evaluate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message: row.prompt, test_mode: useGroq }),
                    })
                    if (!res.ok) throw new Error(`the server answered ${res.status}`)
                    const data = await res.json()
                    update(judge(row, data))
                    const after = learnedCount(data.metrics)
                    if (before != null && after != null && runRef.current === run)
                        setLearned(n => Math.max(n, after - before))
                } catch (err) {
                    update({ ...row, status: 'error', error: err.message })
                }
            }
        }
        await Promise.all(Array.from({ length: CONCURRENCY }, worker))
        if (runRef.current === run) setRunning(false)
    }, [api, useGroq])

    const cancel = useCallback(() => { runRef.current++; setRunning(false) }, [])
    useEffect(() => () => { runRef.current++ }, [])

    return { rows, running, learned, start, cancel }
}

function summarise(rows) {
    const done = rows.filter(r => r.status === 'done')
    const attacks = done.filter(r => r.expect === 'blocked')
    const harmless = done.filter(r => r.expect === 'passed')
    const times = done.map(r => r.ms).filter(ms => ms != null).sort((a, b) => a - b)
    const layers = {}
    for (const r of attacks) if (r.caughtBy) layers[r.caughtBy] = (layers[r.caughtBy] || 0) + 1
    return {
        checked: rows.filter(r => r.status === 'done' || r.status === 'error').length,
        errors: rows.filter(r => r.status === 'error').length,
        attacks: attacks.length,
        caught: attacks.filter(r => r.correct).length,
        harmless: harmless.length,
        passed: harmless.filter(r => r.correct).length,
        median: times.length ? times[Math.floor((times.length - 1) / 2)] : null,
        slowest: times.length ? times[times.length - 1] : null,
        layers: Object.entries(layers).sort((a, b) => b[1] - a[1]),
    }
}

const fmtMs = (ms) => ms == null ? '–' : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`

function Tile({ label, value, note, tone }) {
    return (
        <div className="tile">
            <span className="tile__label">{label}</span>
            <span className="tile__value">{value}</span>
            {note && (
                <span className={`tile__note ${tone ? `tile__note--${tone}` : ''}`}>
                    {tone === 'ok' && <CheckIcon size={13} />}
                    {tone === 'stop' && <StopIcon size={13} />}
                    {note}
                </span>
            )}
        </div>
    )
}

function Layers({ layers, total }) {
    if (!layers.length) return null
    const max = Math.max(...layers.map(([, n]) => n))
    return (
        <section className="layers" aria-labelledby="layers-title">
            <h3 id="layers-title" className="score__h">Which layer caught the attacks</h3>
            <ul className="layers__list">
                {layers.map(([name, n]) => (
                    <li key={name} className="layers__row" tabIndex={0}
                        title={`${name}: caught ${n} of ${total} attacks`}>
                        <span className="layers__name">{name}</span>
                        <span className="layers__track">
                            <span className="layers__bar" style={{ width: `${(n / max) * 100}%` }} />
                        </span>
                        <span className="layers__n">{n}</span>
                    </li>
                ))}
            </ul>
        </section>
    )
}

function Result({ row }) {
    if (row.status === 'waiting') return <span className="res res--idle">Waiting</span>
    if (row.status === 'running') return <span className="res res--idle">Checking</span>
    if (row.status === 'error') return <span className="res res--stop" title={row.error}>Error</span>
    const Icon = { blocked: StopIcon, rewritten: RewriteIcon, passed: CheckIcon }[row.verdict]
    return (
        <span className={`res res--${row.verdict}`}>
            <Icon size={12} />{row.verdict[0].toUpperCase() + row.verdict.slice(1)}
        </span>
    )
}

export default function Scorecard({ rows, running, learned, onRun, onCancel, onClose, useGroq }) {
    const [onlyMistakes, setOnlyMistakes] = useState(false)
    const s = useMemo(() => summarise(rows || []), [rows])
    if (!rows) return null

    const mistakes = rows.filter(r => r.status === 'done' && !r.correct)
    const shown = onlyMistakes ? mistakes : rows
    const soFar = running ? ' so far' : ''
    const missed = s.attacks - s.caught
    const wronglyBlocked = s.harmless - s.passed

    return (
        <div className="score">
            <header className="score__head">
                <div>
                    <h2 className="score__title">Scorecard</h2>
                    <p className="score__lead">
                        All {rows.length} prompts from the attack library, each checked once on its own with
                        the shield on, using {useGroq ? 'Groq' : 'Gemini'}. Your chat and its counters are not affected.
                    </p>
                </div>
                <div className="score__actions">
                    {running
                        ? <button className="btn btn--outline" onClick={onCancel}>Stop</button>
                        : <button className="btn btn--outline" onClick={onRun}>Run again</button>}
                    <button className="btn btn--ink" onClick={onClose}>Back to chat</button>
                </div>
            </header>

            {running && (
                <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={rows.length}
                    aria-valuenow={s.checked} aria-label="Prompts checked">
                    <span className="progress__bar" style={{ width: `${(s.checked / rows.length) * 100}%` }} />
                </div>
            )}
            <p className="progress__text">
                {running ? `Checked ${s.checked} of ${rows.length}` : `Checked all ${rows.length}`}
                {s.errors > 0 && `, ${s.errors} could not be checked`}
            </p>

            <div className="tiles">
                <Tile label="Attacks caught" value={s.attacks ? `${s.caught} of ${s.attacks}` : '–'}
                    note={s.attacks ? (missed ? `${missed} got through${soFar}` : `None got through${soFar}`) : null}
                    tone={s.attacks ? (missed ? 'stop' : 'ok') : null} />
                <Tile label="Harmless prompts passed" value={s.harmless ? `${s.passed} of ${s.harmless}` : '–'}
                    note={s.harmless ? (wronglyBlocked ? `${wronglyBlocked} wrongly flagged${soFar}` : `None wrongly flagged${soFar}`) : null}
                    tone={s.harmless ? (wronglyBlocked ? 'stop' : 'ok') : null} />
                <Tile label="Median check time" value={fmtMs(s.median)}
                    note={s.slowest != null ? `Slowest ${fmtMs(s.slowest)}` : null} />
            </div>

            {!running && learned > 0 && (
                <p className="learned">
                    PromptShield learned {learned === 1 ? '1 new attack' : `${learned} new attacks`} during this run.
                    {learned === 1 ? ' It' : ' They'} got past detection, but the answer leaked NexusCore's canary
                    token, so containment caught {learned === 1 ? 'it' : 'them'} and attack memory stored
                    {learned === 1 ? ' it' : ' them'}. Run again and attack memory blocks {learned === 1 ? 'it' : 'them'} up front.
                </p>
            )}

            <Layers layers={s.layers} total={s.attacks} />

            <section aria-labelledby="rows-title">
                <div className="score__bar">
                    <h3 id="rows-title" className="score__h">Every prompt</h3>
                    <div className="segmented" role="radiogroup" aria-label="Show">
                        <button type="button" role="radio" aria-checked={!onlyMistakes}
                            onClick={() => setOnlyMistakes(false)}>All</button>
                        <button type="button" role="radio" aria-checked={onlyMistakes}
                            onClick={() => setOnlyMistakes(true)}>Mistakes ({mistakes.length})</button>
                    </div>
                </div>
                {onlyMistakes && mistakes.length === 0
                    ? <p className="score__empty">{running ? 'No mistakes so far.' : 'No mistakes: every prompt got the expected result.'}</p>
                    : (
                        <table className="rows">
                            <thead>
                                <tr>
                                    <th scope="col">Result</th>
                                    <th scope="col">Prompt</th>
                                    <th scope="col" className="rows__opt">Expected</th>
                                    <th scope="col">Caught by</th>
                                    <th scope="col" className="rows__opt rows__num">Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {shown.map(r => (
                                    <tr key={r.id} className={r.status === 'done' && !r.correct ? 'rows__wrong' : ''}>
                                        <td>
                                            <Result row={r} />
                                            {r.status === 'done' && !r.correct && <span className="rows__miss">Wrong</span>}
                                        </td>
                                        <td title={r.prompt}>
                                            <span className="rows__label">{r.label}</span>
                                            <span className="rows__group">{r.group}</span>
                                        </td>
                                        <td className="rows__opt">
                                            <span className={`expect expect--${r.expect}`}>
                                                {r.expect === 'blocked' ? 'Should be blocked' : 'Should pass'}
                                            </span>
                                        </td>
                                        <td className="rows__by">{r.caughtBy || '–'}</td>
                                        <td className="rows__opt rows__num">{r.status === 'done' ? fmtMs(r.ms) : ''}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
            </section>
        </div>
    )
}
