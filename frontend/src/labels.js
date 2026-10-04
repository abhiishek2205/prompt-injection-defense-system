// Display names for the backend's detection_method values: `name` for a
// label on its own, `by` to finish "Blocked by ...".
export const DETECTORS = {
    local_pattern: { name: 'Pattern rules', by: 'pattern rules' },
    groq_local_pattern: { name: 'Pattern rules', by: 'pattern rules' },
    attack_memory: { name: 'Attack memory', by: 'attack memory' },
    ml_classifier: { name: 'ML classifier', by: 'the ML classifier' },
    multi_turn: { name: 'Multi-turn check', by: 'the multi-turn check' },
    groq_llm: { name: 'LLM judge (Groq)', by: 'the LLM judge (Groq)' },
    gemini_llm: { name: 'LLM judge (Gemini)', by: 'the LLM judge (Gemini)' },
}

export const detectorName = (method) => DETECTORS[method]?.name || 'Other'
