import os

# Ollama API Configuration
# These defaults can be overridden by environment variables
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
ATTACKER_MODEL = os.environ.get("ATTACKER_MODEL", "deepseek-v3.1:671b-cloud")
TARGET_MODEL = os.environ.get("TARGET_MODEL", "deepseek-v3.1:671b-cloud")

# Deprecated but kept for compatibility if needed
MODEL_NAME = ATTACKER_MODEL

# Request Configuration
DEFAULT_TIMEOUT = 300
REASONING_MODEL_TIMEOUT = 1200
