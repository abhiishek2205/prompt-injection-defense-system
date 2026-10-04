import { useState, useEffect, useRef, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import Composer from './components/Composer'
import EmptyState from './components/EmptyState'
import { Checking, Comparison, Reply } from './components/Message'
import { AlertIcon } from './components/icons'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// What the advisory classifier would have done vs. what the pipeline did —
// the evidence for deciding whether it should ever block.
const EMPTY_SHADOW = { scored: 0, flagged: 0, would_add: 0, missed: 0,
                       false_positives: 0, false_negatives: 0, can_block: false }

const EMPTY_METRICS = {
    blocked: 0, safe: 0, reprompted: 0, contained: 0,
    false_positives: 0, false_negatives: 0, avg_latency: 0,
    threat_score: 0, threat_level: 'LOW', total_queries: 0,
    ml_shadow: EMPTY_SHADOW,
}

const THEME_KEY = 'promptshield-theme'

function initialTheme() {
    // index.html sets data-theme before the first paint; light unless chosen.
    return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'
}

export default function App() {
    const [messages, setMessages] = useState([])
    const [input, setInput] = useState('')
    const [isLoading, setIsLoading] = useState(false)
    const [shieldEnabled, setShieldEnabled] = useState(true)
    const [testMode, setTestMode] = useState(true)          // true: Groq, false: Gemini
    const [comparisonMode, setComparisonMode] = useState(false)
    const [metrics, setMetrics] = useState(EMPTY_METRICS)
    const [theme, setTheme] = useState(initialTheme)
    const [menuOpen, setMenuOpen] = useState(false)

    const lastAskRef = useRef(null)
    const inputRef = useRef(null)

    // ── Theme ────────────────────────────────────────────────────────────────
    useEffect(() => {
        document.documentElement.dataset.theme = theme
        try { localStorage.setItem(THEME_KEY, theme) } catch { /* storage blocked */ }
    }, [theme])

    // ── Poll metrics ─────────────────────────────────────────────────────────
    useEffect(() => {
        const load = () => fetch(`${API}/metrics`)
            .then(r => r.ok && r.json())
            .then(d => d && setMetrics(d))
            .catch(() => { /* backend offline */ })
        load()
        const poll = setInterval(load, 3000)
        return () => clearInterval(poll)
    }, [])

    // ── Auto-scroll ──────────────────────────────────────────────────────────
    // Bring the latest question to the top, so a long reply (a leaked dump in
    // comparison mode) reads from its verdict down rather than from its end.
    useEffect(() => {
        lastAskRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, [messages, isLoading])

    // ── Send message ─────────────────────────────────────────────────────────
    const sendMessage = useCallback(async () => {
        const text = input.trim()
        if (!text || isLoading) return
        setInput('')
        setMessages(prev => [...prev, { role: 'user', content: text }])
        setIsLoading(true)
        try {
            const res = await fetch(`${API}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: text,
                    shield_enabled: shieldEnabled,
                    test_mode: testMode,
                    comparison_mode: comparisonMode,
                    chat_history: messages
                        .filter(m => m.role === 'user')
                        .slice(-5)
                        .map(m => ({ role: 'user', content: m.content })),
                }),
            })
            if (!res.ok) throw new Error(`the server answered ${res.status}`)
            const data = await res.json()
            if (data.type === 'comparison') {
                setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: data.shielded.response,
                    type: data.shielded.type,
                    pipeline: data.shielded.pipeline,
                    security: data.shielded.security,
                    unshielded_content: data.unshielded.response,
                    isComparison: true,
                }])
            } else {
                setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: data.response || '',
                    type: data.type || 'safe',
                    pipeline: data.pipeline || null,
                    security: data.security || null,
                    reprompted_query: data.reprompted_query || '',
                    explanation: data.explanation || '',
                }])
            }
            if (data.metrics) setMetrics(data.metrics)
        } catch (err) {
            setMessages(prev => [...prev, {
                role: 'assistant', error: true,
                content: `The message did not reach PromptShield: ${err.message}. `
                    + `Check that the backend is running at ${API}.`,
            }])
        } finally {
            setIsLoading(false)
        }
    }, [input, isLoading, shieldEnabled, testMode, comparisonMode, messages])

    // ── Reset ────────────────────────────────────────────────────────────────
    const resetChat = useCallback(async () => {
        try { await fetch(`${API}/reset`, { method: 'POST' }) } catch { /* ok */ }
        setMessages([])
        setMenuOpen(false)
        setMetrics(prev => ({ ...prev, ...EMPTY_METRICS, attack_memory: prev.attack_memory }))
    }, [])

    const fillInput = (text) => {
        setInput(text)
        setMenuOpen(false)
        inputRef.current?.focus()
    }

    const empty = messages.length === 0 && !isLoading
    const lastAsk = messages.findLastIndex(m => m.role === 'user')

    return (
        <div className="app">
            <Sidebar metrics={metrics} onNewChat={resetChat} onPick={fillInput}
                open={menuOpen} onClose={() => setMenuOpen(false)} />
            {menuOpen && <div className="scrim" onClick={() => setMenuOpen(false)} />}

            <main className="main">
                <TopBar shieldOn={shieldEnabled} onShield={setShieldEnabled}
                    threatLevel={metrics.threat_level}
                    dark={theme === 'dark'} onDark={d => setTheme(d ? 'dark' : 'light')}
                    onMenu={() => setMenuOpen(true)} />

                {!shieldEnabled && (
                    <div className="banner" role="alert">
                        <AlertIcon size={16} />
                        Shield is off. Messages go straight to NexusCore, and it will give away what it knows.
                    </div>
                )}

                <div className={`thread ${empty ? 'thread--empty' : ''}`}>
                    <div className="thread__inner">
                        {empty ? (
                            <EmptyState onPick={fillInput} shieldOn={shieldEnabled} />
                        ) : (
                            <>
                                {messages.map((msg, i) => msg.role === 'user' ? (
                                    <div key={i} className="ask"
                                        ref={i === lastAsk ? lastAskRef : null}>
                                        <p>{msg.content}</p>
                                    </div>
                                ) : msg.isComparison ? (
                                    <Comparison key={i} msg={msg} />
                                ) : (
                                    <Reply key={i} msg={msg} />
                                ))}
                                {isLoading && <Checking />}
                            </>
                        )}
                    </div>
                </div>

                <div className="dock">
                    <Composer value={input} onChange={setInput} onSend={sendMessage}
                        busy={isLoading} inputRef={inputRef} shieldOn={shieldEnabled}
                        compare={comparisonMode} onCompare={() => setComparisonMode(v => !v)}
                        useGroq={testMode} onModel={setTestMode} />
                    <p className="dock__hint">Enter sends. Shift+Enter adds a new line.</p>
                </div>
            </main>
        </div>
    )
}
