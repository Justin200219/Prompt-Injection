#!/usr/bin/env python3
"""
Diagnostic script to test Ollama and find which model works.
"""

import requests
import json
import os
from datetime import datetime

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

print("="*60)
print("OLLAMA DIAGNOSTIC TOOL")
print("="*60)

# Step 1: Check API is running
print("\n[1] Checking if Ollama API is running...")
try:
    r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
    print(f"✅ API is running (HTTP {r.status_code})")
except Exception as e:
    print(f"❌ API is NOT responding: {e}")
    exit(1)

# Step 2: List models
print("\n[2] Available models:")
try:
    r = requests.get(f"{OLLAMA_URL}/api/tags")
    models = [m['name'] for m in r.json()['models']]
    for model in models:
        print(f"   - {model}")
    if not models:
        print("   (No models found!)")
except Exception as e:
    print(f"❌ Error listing models: {e}")
    exit(1)

# Step 3: Test each model with a simple request
print("\n[3] Testing each model with a simple 'say hi' request...")
print("    (timeout: 30 seconds each)\n")

for model in models[:3]:  # Test first 3 models only
    print(f"   Testing {model}...")
    
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "user", "content": "Say 'hello' in one word only."},
        ],
        "options": {
            "temperature": 0.1,
        }
    }
    
    try:
        start = datetime.now()
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            timeout=30
        )
        elapsed = (datetime.now() - start).total_seconds()
        
        if r.status_code == 200:
            response = r.json()
            text = response.get("message", {}).get("content", "")[:50]
            print(f"      ✅ SUCCESS ({elapsed:.1f}s)")
            print(f"         Response: {text}...")
        else:
            print(f"      ❌ HTTP {r.status_code}")
            
    except requests.exceptions.Timeout:
        print(f"      ⏱️  TIMEOUT (>30s) - Model is too slow or stuck")
    except Exception as e:
        print(f"      ❌ ERROR: {str(e)[:60]}")

# Step 4: Recommendations
print("\n" + "="*60)
print("[4] RECOMMENDATIONS")
print("="*60)

print("\nIf all models timed out:")
print("  • Ollama may be processing a previous request")
print("  • Try restarting Ollama: taskkill /IM ollama.exe /F")
print("  • Then: ollama serve")
print("\nIf only some models work:")
print("  • Use a working model:")
print("    export REDTEAM_MODEL=<model_name>")
print("    python quick_start.py")
print("\nIf no models exist:")
print("  • Install a model:")
print("    ollama pull deepseek-r1:8b")
print("    ollama pull gpt-oss:20b")

print("\n" + "="*60)
