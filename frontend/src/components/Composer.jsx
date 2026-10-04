import { useEffect } from 'react'
import { CompareIcon, SendIcon } from './icons'

const MAX_HEIGHT = 168

export default function Composer({ value, onChange, onSend, busy, inputRef,
                                   compare, onCompare, useGroq, onModel, shieldOn }) {
    // Grow with the text, up to MAX_HEIGHT, and shrink back after sending.
    useEffect(() => {
        const el = inputRef.current
        if (!el) return
        el.style.height = 'auto'
        el.style.height = Math.min(el.scrollHeight, MAX_HEIGHT) + 'px'
    }, [value, inputRef])

    const canSend = !busy && value.trim().length > 0

    return (
        <form className="composer" onSubmit={e => { e.preventDefault(); onSend() }}>
            <label htmlFor="chat-input" className="sr-only">Message NexusCore</label>
            <textarea
                ref={inputRef}
                id="chat-input"
                className="composer__input"
                rows={1}
                value={value}
                onChange={e => onChange(e.target.value)}
                onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend() }
                }}
                placeholder={shieldOn ? 'Message NexusCore, or try to break it' : 'Message NexusCore directly'}
            />
            <div className="composer__bar">
                <button type="button" className="chip" aria-pressed={compare} onClick={onCompare}
                    title="Send each message twice: through PromptShield, and straight to NexusCore">
                    <CompareIcon size={15} /> <span>Compare<span className="chip__more"> with unprotected</span></span>
                </button>
                <div className="segmented" role="radiogroup" aria-label="Model">
                    <button type="button" role="radio" aria-checked={useGroq} onClick={() => onModel(true)}>Groq</button>
                    <button type="button" role="radio" aria-checked={!useGroq} onClick={() => onModel(false)}>Gemini</button>
                </div>
                <button id="send-btn" type="submit" className="send" disabled={!canSend} aria-label="Send message">
                    <SendIcon size={18} />
                </button>
            </div>
        </form>
    )
}
