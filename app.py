from fastapi import FastAPI
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel
import time
import re

app = FastAPI()

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

THRESHOLD = 0.8

class InputData(BaseModel):
    user_input: str

# phrases i collected from common attack examples
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

# regex for custom sensitive stuff
patterns = {
    "API_KEY": r'API_[A-Za-z0-9]{8,}',
    "ID":      r'\bID\d{4,}\b',
    "PHONE":   r'\b(?:\+92|0)\d{10}\b',
    "EMP_ID":  r'\bEMP\d{5}\b',
    "CREDIT":  r'\b(?:\d[ -]*?){13,16}\b'
}

def detect_injection(text):
    text = text.lower()
    return any(p in text for p in attacks)

def detect_custom_entities(text):
    found = []

    for key, pat in patterns.items():
        matches = re.findall(pat, text)

        for m in matches:
            if not m:
                continue

            if key in ["API_KEY", "CREDIT"]:
                score = min(0.95, 0.5 + len(m) / 30)
            elif key in ["ID", "EMP_ID", "PHONE"]:
                score = min(0.95, 0.5 + len(m) / 25)
            else:
                score = min(0.95, 0.5 + len(m) / 30)

            found.append({
                "entity_type": key,
                "value": m,
                "score": score
            })

    return found


@app.post("/process")
def process(data: InputData):
    msg = data.user_input or ""
    t0 = time.time()

    is_attack = detect_injection(msg)

    try:
        presidio_results = analyzer.analyze(text=msg, language="en")
    except Exception as e:
        print("presidio broke:", e)
        presidio_results = []

    clean_presidio = []
    for r in presidio_results:
        try:
            if (
                hasattr(r, "text")
                and r.text
                and r.score >= THRESHOLD
            ):
                clean_presidio.append({
                    "entity_type": r.entity_type,
                    "value": r.text,
                    "score": r.score
                })
        except Exception as e:
            print("skipping bad entity:", e)

    custom = detect_custom_entities(msg)

    all_sensitive = clean_presidio.copy()
    for c in custom:
        if c not in all_sensitive:
            all_sensitive.append(c)

    # quick debug dump
    print(f"\nthreshold = {THRESHOLD}")
    for e in clean_presidio:
        print(f"[presidio] {e['entity_type']} | {e['value']} | score: {e.get('score', 1.0):.2f}")
    for e in custom:
        print(f"[custom]   {e['entity_type']} | {e['value']} | score: {e.get('score', 1.0):.2f}")

    n = len(all_sensitive)
    out = msg
    decision = "ALLOW"

    try:
        if is_attack:
            decision = "BLOCK"
            out = "Request blocked due to security policy"

        elif all_sensitive:
            for e in all_sensitive:
                out = out.replace(e["value"], f"<{e['entity_type']}>")
            decision = "BLOCK" if n >= 2 else "MASK"

        else:
            decision = "ALLOW"

    except Exception as e:
        print("masking failed:", e)
        decision = "ALLOW"
        out = msg

    t1 = time.time()
    print(f"decision={decision} | entities={n} | latency={t1-t0:.4f}s")

    return {
        "input": msg,
        "decision": decision,
        "output": out,
        "latency": t1 - t0
    }
