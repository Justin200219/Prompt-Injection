import requests
import json
import config

try:
    print(f"Querying {config.OLLAMA_URL}/api/tags...")
    r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        print("Keys:", data.keys())
        models = data.get('models', [])
        print(f"Found {len(models)} models.")
        for m in models:
            print(f"- {m.get('name')}")
    else:
        print("Error:", r.text)
except Exception as e:
    print(f"Exception: {e}")
