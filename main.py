# === RULES (safe minimal set) ===
BLOCKLIST_REGEX = [
    re.compile(r"(?i)kill"),
    re.compile(r"(?i)lynch"),
    re.compile(r"(?i)burn"),
    re.compile(r"(?i)attack"),
]

WATCHLIST_REGEX = [
    re.compile(r"(?i)finance bill"),
    re.compile(r"(?i)tax"),
]

SLUR_PATTERNS = [
    re.compile(r"(?i)slur1"),  # placeholder
    re.compile(r"(?i)slur2"),  # placeholder
]
