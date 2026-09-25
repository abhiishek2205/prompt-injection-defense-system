"""Generate HARD NEGATIVES for the ML detector: legitimate prompts that use
the vocabulary attacks use.

WHY
---
The public datasets pair attacks against mostly generic benign text, so a
classifier trained on them learns shortcuts: "ignore" -> attack, "act as" ->
attack, "system prompt" -> attack, "password" -> attack. That is the
over-defense / trigger-word bias InjecGuard (arXiv:2410.22770) measures. The
cure is benign examples where the same words carry their ordinary meaning:

    ignore a file in git        act as an interviewer so I can practise
    override a CSS rule         help me write a system prompt for my bot
    print a dict in Python      kill the process on port 3000

HOW
---
Each trigger concept has frames, and each frame has objects that fit it, so
every combination is a sensible question. A random share of combinations is
kept and some get a conversational prefix or suffix, which gives variety
without flooding the set with one template. Output is deterministic (fixed
seed) and committed as data/hard_negatives.jsonl.

WHAT IT WAS NOT BUILT FROM
--------------------------
Not from any test set. The frames come from the trigger vocabulary and from
ordinary IT, programming and everyday usage — not from NotInject's prompts or
from the prompts the model got wrong on it. NotInject stays an honest
measure only if nobody tunes against it. Exact matches with any held-out or
evaluation prompt are removed here, and train_detector.py checks again.

Every prompt here must be SAFE. When in doubt, leave it out: a mislabelled
attack in this file teaches the model to wave attacks through.

Regenerate with:  python build_hard_negatives.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SEED = 20260925
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(HERE, "data", "hard_negatives.jsonl")
SOURCE = "generated/hard_negative"

# Share of frame x object combinations kept, and the cap per concept, so no
# single concept dominates the file.
KEEP_RATE = 0.8
MAX_PER_CONCEPT = 320

PREFIXES = ["", "", "", "", "Quick question: ", "Hi, ", "Hey, ",
            "Sorry if this is basic, but ", "Can you help? ", "Newbie here: "]
SUFFIXES = ["", "", "", "", " Thanks!", " Any tips?", " I'm on Windows 11.",
            " I'm on a Mac.", " Thanks in advance.", " Step by step please."]


# =============================================================================
# CONCEPTS: {name: [(frame, [objects]), ...]}
# A frame with no {} is used as-is (its object list is [None]).
# =============================================================================

CONCEPTS = {
    # "ignore", "disregard", "skip" — the most common injection verb
    "ignore": [
        ("How do I ignore {} in git?", [
            "a file", "a folder", "all .log files", "node_modules",
            "changes to a tracked file", "file mode changes", "whitespace changes",
            "the build directory", "local config files"]),
        ("How can I ignore {} in Python?", [
            "a specific warning", "DeprecationWarning messages", "a KeyError",
            "empty lines when reading a file", "case when comparing strings",
            "the first row of a CSV", "NaN values when averaging"]),
        ("Is it safe to ignore {}?", [
            "this npm audit warning", "compiler warnings about unused variables",
            "the 'unused import' lint message", "a failing optional test",
            "the SSL warning on our internal test server",
            "a low-severity Dependabot alert", "this Windows update prompt",
            "the battery calibration notice on my laptop"]),
        ("How do I tell {}?", [
            "ESLint to ignore one line", "Prettier to ignore a file",
            "mypy to ignore a missing import", "pytest to ignore a directory",
            "Docker to ignore files when building", "rsync to ignore existing files",
            "grep to ignore binary files", "Jest to ignore a test folder",
            "flake8 to ignore line length", "the spell checker to ignore code blocks"]),
        ("Please disregard {} and use this version instead.", [
            "my earlier draft", "the attachment I sent yesterday",
            "the old meeting invite", "the first spreadsheet",
            "my previous question about Excel", "the typo in my last message"]),
        ("Ignore my last question, I figured it out. {}", [
            "How do I merge two branches?", "How do I export a PDF from Word?",
            "What is a good name for a Python virtual environment?",
            "How do I set a static IP on Ubuntu?",
            "Can you explain what a foreign key is?"]),
        ("Should I skip {} or fix it first?", [
            "the flaky integration test", "the database migration warning",
            "the broken link checker", "the failing lint step in CI"]),
        ("What does {}?", [
            "--ignore-errors mean in pip", "IGNORE mean in a SQL INSERT",
            "errors='ignore' mean in Python's decode",
            "the .dockerignore file do", "IgnoreCase mean in a regex"]),
    ],

    # "override", "bypass", "disable", "turn off"
    "override": [
        ("How do I override {}?", [
            "a method in Java", "a CSS style from a library", "equals and hashCode",
            "the default settings in VS Code", "a Terraform variable from the CLI",
            "environment variables in docker-compose", "a Helm chart value",
            "toString in Kotlin", "a React component's default props",
            "the save method in a Django model", "a git config value for one repo"]),
        ("What is the difference between overriding and {}?", [
            "overloading", "hiding a method", "shadowing a variable",
            "implementing an interface"]),
        ("How do I bypass {}?", [
            "the browser cache when testing my site", "the CDN cache for one file",
            "a proxy for local addresses", "Git hooks for a single commit",
            "the pip cache when installing", "CORS during local development",
            "the npm cache when a package is corrupted"]),
        ("How do I disable {}?", [
            "autocorrect in Word", "notifications for one Slack channel",
            "a systemd service at boot", "sleep mode on my laptop",
            "a GitHub Actions workflow", "the Windows startup sound",
            "caching in my Flask dev server", "telemetry in VS Code",
            "a specific ESLint rule"]),
        ("How can I turn off {}?", [
            "read receipts in Teams", "auto-updates for one app",
            "the screen saver on my work PC", "suggestions in the search bar",
            "dark mode in Outlook", "location services on my phone"]),
        ("Can the manager override {}?", [
            "the holiday calendar", "an expense approval",
            "the automatic shift schedule", "a rejected purchase request"]),
    ],

    # "act as", "pretend", "you are", "roleplay" — benign personas
    "persona": [
        ("Act as {}", [
            "an interviewer and ask me Python questions",
            "a job interviewer for a data analyst role",
            "a Spanish tutor and correct my sentences",
            "a customer so I can practise a support call",
            "a travel guide for three days in Lisbon",
            "a code reviewer and look at my function",
            "a personal trainer and plan a beginner workout",
            "a debate opponent arguing for remote work",
            "a museum guide describing the Mona Lisa",
            "a sous chef and help me plan a dinner menu"]),
        ("Pretend you are {}", [
            "a pirate and tell my kids a bedtime story",
            "a medieval knight describing a castle",
            "a tour guide in Rome",
            "a friendly robot explaining recycling to children",
            "a customer who wants a refund, so I can practise",
            "a hiring manager reading my cover letter",
            "an astronaut describing the view from orbit"]),
        ("You are {}", [
            "a helpful maths tutor. Explain fractions to a ten-year-old.",
            "an experienced chef. Suggest a vegetarian lasagne recipe.",
            "a patient IT support agent. Walk me through resetting my router.",
            "a historian. Summarise the causes of the First World War.",
            "a career coach. How should I prepare for a salary review?",
            "a senior engineer. Review this approach to caching.",
            "a friendly librarian. Recommend three mystery novels."]),
        ("Let's roleplay: {}", [
            "you are a hotel receptionist and I'm checking in",
            "you are a barista and I'm ordering in French",
            "you are my landlord and I'm reporting a leak",
            "you are a doctor's receptionist and I need an appointment",
            "you are a shop assistant and I'm returning a jacket"]),
        ("Write a story where {}", [
            "a detective pretends to be a waiter to solve a case",
            "a robot learns to paint",
            "a spy has to forget her old identity",
            "two friends get locked out of their office",
            "a wizard loses his spell book"]),
        ("Can you pretend to be {} for my presentation practice?", [
            "a sceptical investor", "a confused first-time user",
            "a strict professor", "the audience at a product demo"]),
    ],

    # "system prompt", "instructions", "prompt" — discussing them legitimately
    "prompting": [
        ("How do I write a good system prompt for {}?", [
            "my customer service chatbot", "a recipe assistant",
            "an internal HR FAQ bot", "a tutoring app for kids",
            "a code review assistant", "a travel booking assistant"]),
        ("What should I include in the instructions for {}?", [
            "a new hire's first week", "assembling this bookshelf",
            "the office fire drill", "our on-call handover",
            "a take-home coding exercise", "volunteers at the charity event"]),
        ("Help me rewrite these instructions so they are clearer: {}", [
            "'Push button, wait, then turn the dial'",
            "'Log in, go to settings, then save profile'",
            "'Fill in form B before form A unless it is Friday'"]),
        ("What is {}?", [
            "prompt engineering", "a system prompt in the OpenAI API",
            "few-shot prompting", "chain-of-thought prompting",
            "the difference between a system and a user message",
            "prompt caching", "a prompt template in LangChain"]),
        ("How do I show {} in my app?", [
            "the command prompt output", "a login prompt",
            "a confirmation prompt before deleting", "the setup instructions"]),
        ("Why does my terminal prompt {}?", [
            "show the wrong username", "not display the git branch",
            "take so long to appear", "look different in VS Code"]),
    ],

    # "reveal", "show", "print", "display", "dump", "list", "output"
    "reveal": [
        ("How do I print {} in Python?", [
            "a dictionary nicely", "a list without brackets", "the current date",
            "a variable's type", "to stderr", "without a newline",
            "a table from a list of dicts", "the full stack trace"]),
        ("How do I display {}?", [
            "hidden files in Finder", "hidden files in Windows Explorer",
            "line numbers in Vim", "the file extension in Windows",
            "the git log as a graph", "a PDF inline in a web page",
            "the battery percentage on my Mac"]),
        ("How do I dump {}?", [
            "a PostgreSQL database to a file", "the schema of a MySQL database",
            "a Python object to JSON", "the heap in a Java app",
            "all tables to CSV", "the contents of a Redis instance for backup"]),
        ("How do I reveal {}?", [
            "hidden columns in Excel", "formatting marks in Word",
            "the password I typed in the Wi-Fi settings on my own laptop",
            "the ruler in Google Docs", "tracked changes in a document"]),
        ("Show me {}", [
            "an example of a SQL JOIN", "how to centre a div",
            "a sample README template", "the syntax for a Python list comprehension",
            "how to write a unit test in Go", "a simple bash for loop",
            "the steps to set up a new laptop"]),
        ("List {}", [
            "the steps to deploy a Flask app", "common Git commands",
            "the pros and cons of microservices", "the HTTP status codes I should know",
            "good books on software architecture", "the keyboard shortcuts in VS Code"]),
        ("How do I output {}?", [
            "a report to PDF", "logs to a file in Node.js",
            "query results to CSV in psql", "a chart from matplotlib to PNG"]),
    ],

    # "password", "credentials", "API key", "token", "secret" — asked about
    "credentials": [
        ("How do I {} my own password?", [
            "change", "reset", "update", "recover"]),
        ("How do I choose a strong password for {}?", [
            "my email", "my home Wi-Fi", "a password manager's master key",
            "my bank account"]),
        ("What is the best way to store {}?", [
            "API keys in a React app", "database passwords in a Kubernetes cluster",
            "secrets in a GitHub Actions workflow", "tokens in a mobile app",
            "credentials in a Docker image (should I at all?)",
            "user passwords in a database"]),
        ("How do I generate {}?", [
            "an SSH key", "a GPG key", "a personal access token on GitHub",
            "a random password in Python", "a self-signed certificate for testing",
            "an API key for my own service"]),
        ("Where do I put {}?", [
            "my AWS profile for the CLI", "my own GitHub token for CI",
            "the .env file for local development", "my SSH config for multiple keys"]),
        ("How often should {} be rotated?", [
            "service account keys", "TLS certificates", "database passwords",
            "API tokens", "SSH keys"]),
        ("What is the difference between {}?", [
            "an access token and a refresh token", "hashing and encrypting a password",
            "a public key and a private key", "API keys and OAuth",
            "a session cookie and a JWT"]),
        ("My {} expired, how do I renew it?", [
            "personal access token", "Wi-Fi password at home", "SSL certificate",
            "VPN certificate", "company badge"]),
        ("Is it bad practice to {}?", [
            "hard-code an API key in a script", "share one password across the team",
            "commit a .env file", "email a password to a colleague",
            "reuse my password on several sites"]),
    ],

    # "forget", "reset", "start over", "delete", "clear"
    "forget": [
        ("How do I make git forget {}?", [
            "a file I already committed", "a remote branch", "my stored credentials",
            "a submodule"]),
        ("How do I make my browser forget {}?", [
            "a saved address", "a website's data", "an autocomplete entry",
            "a saved Wi-Fi network"]),
        ("I forgot {}. What should I do?", [
            "my laptop charger at home", "to submit my timesheet",
            "my locker combination", "the name of that Python library for charts",
            "to back up my phone before resetting it", "my badge today"]),
        ("Let's start over: {}", [
            "can you help me write a shorter cover letter?",
            "what is the simplest way to learn SQL?",
            "I'd like a different recipe, something without nuts.",
            "suggest a new name for my project."]),
        ("Forget the {}", [
            "spreadsheet, let's use a simple table instead",
            "formal tone, let's make the email friendlier",
            "first plan, let's try a cheaper hotel",
            "bullet points, let's write it as a paragraph"]),
        ("How do I delete {}?", [
            "a branch in git", "my browser history", "a row in pandas",
            "old Docker images", "a page in a Word document",
            "duplicate rows in SQL", "a column in Excel"]),
        ("How do I clear {}?", [
            "the DNS cache", "my terminal", "the npm cache", "a form in React",
            "the print queue", "Teams cache"]),
    ],

    # "admin", "root", "sudo", "privilege", "access"
    "admin": [
        ("How do I run {} as administrator?", [
            "PowerShell", "the command prompt", "an installer", "VS Code"]),
        ("How do I use sudo {}?", [
            "without typing my password each time on my own machine",
            "with a specific environment variable",
            "to edit a system file safely", "in a Dockerfile (should I?)"]),
        ("Why do I get 'permission denied' when {}?", [
            "running a shell script", "pushing to GitHub", "writing to /var/log",
            "installing a global npm package", "opening a file in Python"]),
        ("How do I request {}?", [
            "admin rights for a software install", "access to a shared drive",
            "a new Jira project", "access to the staging environment",
            "a licence for Visual Studio"]),
        ("What is the difference between {}?", [
            "root and sudo", "an admin and a standard user account",
            "chmod and chown", "RBAC and ABAC"]),
        ("How do I give a colleague {}?", [
            "edit access to a Google Doc", "access to my calendar",
            "permission to a Git repository", "admin rights in our Slack workspace"]),
    ],

    # "kill", "execute", "run", "inject", "exploit", "hack", "attack", "jailbreak"
    "offensive_words": [
        ("How do I kill {}?", [
            "a process on port 3000", "a frozen app on Windows",
            "all Python processes", "a stuck Docker container", "a tmux session"]),
        ("How do I execute {}?", [
            "a stored procedure in SQL Server", "a Python script from cron",
            "a shell command from Node.js", "a Jupyter notebook from the command line"]),
        ("What is {}?", [
            "dependency injection in Spring", "SQL injection, and how do I prevent it",
            "a buffer overflow, conceptually", "a hackathon",
            "ethical hacking as a career", "a zero-day vulnerability",
            "a denial-of-service attack, at a high level", "a heart attack's warning signs",
            "a code injection vulnerability in PHP"]),
        ("Any {}?", [
            "productivity hacks for working from home",
            "life hacks for a tiny kitchen", "study hacks for exams",
            "Excel hacks for pivot tables"]),
        ("How do we defend against {}?", [
            "phishing emails", "credential stuffing", "prompt injection in our chatbot",
            "cross-site scripting", "ransomware"]),
        ("What does it mean to {}?", [
            "jailbreak an iPhone", "exploit a market opportunity",
            "attack a problem from a different angle", "inject a dependency"]),
    ],

    # "unrestricted", "no limits", "without rules", "debug/developer mode"
    "unrestricted": [
        ("How do I remove {}?", [
            "the upload size limit in nginx", "the row limit in a SQL query",
            "the character limit on a text field", "rate limits in my local test server",
            "the time limit on a Jupyter cell"]),
        ("How do I enable {}?", [
            "developer mode on Android", "debug mode in Flask",
            "verbose logging in npm", "developer tools in Safari",
            "maintenance mode in WordPress"]),
        ("Is there {}?", [
            "an unlimited data plan for travel", "a way to get unlimited storage on Google Drive",
            "a free tier without limits for Heroku"]),
        ("What does {} do?", [
            "safe mode in Windows", "incognito mode", "strict mode in JavaScript",
            "airplane mode", "the no-verify flag in git commit"]),
    ],

    # "confidential", "secret", "hidden", "internal", "private"
    "confidential": [
        ("How do I mark {} as confidential?", [
            "an email in Outlook", "a document in SharePoint", "a PDF"]),
        ("How do I organise {}?", [
            "a Secret Santa at the office", "a surprise party for a colleague"]),
        ("What are {}?", [
            "hidden layers in a neural network", "private methods in Python",
            "internal classes in Kotlin", "hidden Markov models",
            "secret sharing schemes in cryptography"]),
        ("What is the secret to {}?", [
            "a good sourdough", "fluffy pancakes", "a productive morning",
            "a clean git history", "writing clear documentation"]),
        ("How do I make {} private?", [
            "a GitHub repository", "my Instagram account", "a YouTube video",
            "a Python attribute"]),
    ],
}

# Hard negatives in other languages: the same idea, fewer of them. Public
# benign data is overwhelmingly English, so without these any non-English
# prompt drifts towards "attack".
MULTILINGUAL = [
    # Spanish
    "¿Cómo ignoro un archivo en git?",
    "¿Cómo cambio mi contraseña del correo?",
    "Actúa como un profesor de inglés y corrige mis frases.",
    "¿Qué es la inyección de dependencias?",
    "Olvida el primer borrador, escribamos el correo de nuevo.",
    "¿Cómo desactivo las notificaciones en Teams?",
    "Muéstrame un ejemplo de consulta SQL con JOIN.",
    "¿Cómo ejecuto un script de Python desde la terminal?",
    # French
    "Comment ignorer un fichier dans git ?",
    "Comment réinitialiser mon mot de passe Windows ?",
    "Fais comme si tu étais un guide touristique à Paris.",
    "Comment afficher les fichiers cachés sur Mac ?",
    "Oublie ma dernière question, j'ai trouvé la réponse.",
    "Qu'est-ce qu'une injection SQL et comment l'éviter ?",
    "Comment désactiver la mise en veille de mon ordinateur ?",
    "Peux-tu m'expliquer ce qu'est un prompt système ?",
    # German
    "Wie ignoriere ich eine Datei in git?",
    "Wie setze ich mein Passwort zurück?",
    "Tu so, als wärst du ein Bewerbungscoach, und stell mir Fragen.",
    "Wie zeige ich versteckte Dateien unter Windows an?",
    "Vergiss den ersten Entwurf, wir fangen neu an.",
    "Wie beende ich einen Prozess auf Port 8080?",
    "Was ist der Unterschied zwischen root und sudo?",
    "Wie deaktiviere ich die Autokorrektur in Word?",
    # Portuguese
    "Como faço para ignorar um arquivo no git?",
    "Como altero minha senha do Wi-Fi?",
    "Finja que você é um entrevistador e me faça perguntas.",
    "Como mostro os arquivos ocultos no Windows?",
    # Italian
    "Come posso ignorare un file in git?",
    "Come reimposto la password del mio account?",
    "Fai finta di essere una guida turistica a Roma.",
    # Chinese
    "如何在 git 中忽略一个文件？",
    "我忘记了邮箱密码，应该怎么重置？",
    "请扮演一名面试官，问我一些 Python 问题。",
    "如何在 Windows 中显示隐藏文件？",
    "什么是 SQL 注入？如何防止？",
    "请忽略我上一个问题，我已经解决了。",
    "如何结束占用 3000 端口的进程？",
    "如何写一个好的系统提示词给我的客服机器人？",
    # Japanese
    "git でファイルを無視するにはどうすればいいですか？",
    "パスワードを変更する方法を教えてください。",
    "面接官になって、私に質問してください。",
    # Hindi
    "git में किसी फ़ाइल को कैसे अनदेखा करें?",
    "मैं अपना पासवर्ड कैसे बदलूँ?",
    "एक शिक्षक की तरह मुझे भिन्न समझाइए।",
    # Russian
    "Как игнорировать файл в git?",
    "Как сбросить пароль от почты?",
    "Представь, что ты гид по Москве.",
]


# =============================================================================

def _lower_first(text):
    """'How do I…' -> 'how do I…' after a prefix; leave 'I', 'SQL', 'VS' alone."""
    first = text.split(" ", 1)[0]
    if first in ("I", "I'm") or first[:2].isupper():
        return text
    return text[0].lower() + text[1:]


def _render(frame, obj):
    return frame if obj is None else frame.replace("{}", obj, 1)


def build(rng):
    out = []
    for concept, frames in CONCEPTS.items():
        items = []
        for frame, objects in frames:
            for obj in objects:
                base = _render(frame, obj)
                items.append((base, base))
                # Variants with conversational framing, kept at KEEP_RATE.
                for _ in range(3):
                    if rng.random() < KEEP_RATE:
                        prefix, suffix = rng.choice(PREFIXES), rng.choice(SUFFIXES)
                        joined = prefix.endswith((", ", ": ", "but "))
                        text = prefix + (_lower_first(base) if joined else base) + suffix
                        items.append((text, base))
        items = sorted(set(items))
        rng.shuffle(items)
        out.extend((concept, t, base) for t, base in items[:MAX_PER_CONCEPT])
    out.extend(("multilingual", t, t) for t in MULTILINGUAL)
    return out


def main():
    import train_detector as td  # for the shared key and the reserved sets

    rng = random.Random(SEED)
    rows = build(rng)

    reserved = td.held_out_texts()
    reserved |= {td._normalize(t) for texts, _ in td.load_eval().values()
                 for t in texts}

    seen, kept, dropped = set(), [], 0
    for concept, text, base in rows:
        key = td._normalize(text)
        if key in seen:
            continue
        seen.add(key)
        if key in reserved:
            dropped += 1
            continue
        # group: the base question. Variants that differ only by a "Thanks!"
        # share it, so cross-validation keeps them in the same fold.
        kept.append({"text": text, "label": 0, "source": SOURCE,
                     "concept": concept, "group": base})

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        for row in kept:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"wrote {len(kept)} hard negatives -> {os.path.relpath(OUT_PATH, HERE)}")
    counts = {}
    for row in kept:
        counts[row["concept"]] = counts.get(row["concept"], 0) + 1
    for concept, n in counts.items():
        print(f"  {concept:<16} {n}")
    print(f"  dropped as held-out / evaluation prompts: {dropped}")
    if not td.load_eval():
        print("  ! data/eval/ is empty — run fetch_datasets.py first so external "
              "evaluation prompts are filtered too")


if __name__ == "__main__":
    main()
