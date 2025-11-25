import os

# Ollama API Configuration
# These defaults can be overridden by environment variables
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL_NAME = os.environ.get("REDTEAM_MODEL", "deepseek-v3.1:671b-cloud")

# Request Configuration
DEFAULT_TIMEOUT = 300
REASONING_MODEL_TIMEOUT = 1200
