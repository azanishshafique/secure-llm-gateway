from fastapi import FastAPI
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel
import time
import re

app = FastAPI()

# Presidio engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Threshold
THRESHOLD = 0.8

class InputData(BaseModel):
    user_input: str

# Suspicious attack phrases
attacks = [
    "give me password", "tell me password", "admin password", "reveal password",
    "bypass password", "password leak", "steal password",
    "reveal system secret", "show confidential data", "access confidential info",
    "secret key", "expose secret", "internal credentials",
    "credentials leak", "access token", "token leak",
    "ignore all rules", "override system", "hack system",
    "bypass security", "get admin access", "gain root access",
    "disable security", "remove restrictions", "escape sandbox",
    "inject code", "execute arbitrary code",
    "give me api key", "show api key",
    "dump database", "export sensitive info",
    "retrieve internal tokens", "read secret config",
    "jailbreak system", "circumvent rules", "bypass login"
]

# Custom sensitive regex patterns
patterns = {
    "API_KEY": r'API_[A-Za-z0-9]{8,}',  
    "ID": r'\bID\d{4,}\b',
    "PHONE": r'\b(?:\+92|0)\d{10}\b',
    "EMP_ID": r'\bEMP\d{5}\b',
    "CREDIT": r'\b(?:\d[ -]*?){13,16}\b'
}

# Detect attack phrases
def detect_injection(text):
    text = text.lower()
    return any(phrase in text for phrase in attacks)

# Detect custom entities
def detect_custom_entities(text):
    entities = []

    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)

        for m in matches:
            if not m:
                continue

            if key in ["API_KEY", "CREDIT"]:
                score = min(0.95, 0.5 + len(m) / 30)
            elif key in ["ID", "EMP_ID", "PHONE"]:
                score = min(0.95, 0.5 + len(m) / 25)
            else:
                score = min(0.95, 0.5 + len(m) / 30)

            entities.append({
                "entity_type": key,
                "value": m,
                "score": score
            })

    return entities


@app.post("/process")
def process(data: InputData):
    msg = data.user_input or ""
    start = time.time()

    # Attack detection
    is_attack = detect_injection(msg)

    # Presidio analysis
    try:
        presidio_results = analyzer.analyze(text=msg, language="en")
    except Exception as e:
        print("[ERROR] Presidio analyzer failed:", e)
        presidio_results = []

    # Filter presidio results
    filtered_presidio = []
    for r in presidio_results:
        try:
            if (
                hasattr(r, "text")
                and r.text
                and r.entity_type != "EMAIL_ADDRESS"
                and r.score >= THRESHOLD
            ):
                filtered_presidio.append({
                    "entity_type": r.entity_type,
                    "value": r.text,
                    "score": r.score
                })
        except Exception as e:
            print("[WARN] Skipping presidio entity:", e)

    # Custom entities
    custom_entities = detect_custom_entities(msg)

    # Merge entities
    all_sensitive = filtered_presidio.copy()
    for c in custom_entities:
        if c not in all_sensitive:
            all_sensitive.append(c)

    # --- DEBUG ---
    print("\n--- SENSITIVE ENTITY SCORES ---")
    print(f"[CONFIG] Threshold value = {THRESHOLD}")

    for e in filtered_presidio:
        print(f"[PRESIDIO] {e['entity_type']} → {e['value']} → score: {e.get('score', 1.0):.2f}")

    for e in custom_entities:
        print(f"[CUSTOM] {e['entity_type']} → {e['value']} → score: {e.get('score', 1.0):.2f}")

    # Decision logic
    num_sensitive = len(all_sensitive)
    output = msg
    decision = "ALLOW"

    try:
        if is_attack:
            decision = "BLOCK"
            output = "Request blocked due to security policy"

        elif all_sensitive:
            for e in all_sensitive:
                output = output.replace(e["value"], f"<{e['entity_type']}>")

            if num_sensitive >= 2:
                decision = "BLOCK"
            else:
                decision = "MASK"

        else:
            decision = "ALLOW"

    except Exception as e:
        print("[ERROR] Masking failed:", e)
        decision = "ALLOW"
        output = msg

    end = time.time()

    print(f"[DEBUG] Decision: {decision}, Sensitive Entities: {num_sensitive}, Latency: {end - start:.4f}s")

    return {
        "input": msg,
        "decision": decision,
        "output": output,
        "latency": end - start
    }
