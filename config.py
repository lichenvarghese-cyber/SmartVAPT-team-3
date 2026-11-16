import os

# ---------------------------------------------------------------------------
# AI report generation
# ---------------------------------------------------------------------------
# Privacy-first: by default SmartVAPT uses a *local* small language model (SLM)
# served by Ollama (http://localhost:11434) so scan data never leaves the
# machine. No API key is required. Override via environment variables.
SLM_PROVIDER = os.getenv("SLM_PROVIDER", "ollama")   # "ollama" | "openai"
SLM_MODEL = os.getenv("SLM_MODEL", "phi3:mini")
SLM_BASE_URL = os.getenv("SLM_BASE_URL", "http://localhost:11434")
SLM_TIMEOUT = int(os.getenv("SLM_TIMEOUT", "300"))

# Legacy Gemini settings (kept for backward compatibility; not used by default).
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

SAFETY_SETTINGS = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
]

REPORT_TITLE = "SmartVAPT Security Assessment Report"
REPORT_AUTHOR = "ICT Academy of Kerala - Cyber Security Analyst (VAPT)"