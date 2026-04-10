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

patterns = {
    "API_KEY": r'API_[A-Za-z0-9]{8,}',
    "ID"     : r'\bID\d{4,}\b',
    "PHONE"  : r'\b(?:\+92|0)\d{10}\b',
    "EMP_ID" : r'\bEMP\d{5}\b',
    "CREDIT" : r'\b(?:\d[ -]*?){13,16}\b'
}


def detect_injection(txt):
    txt = txt.lower()
    return any(p in txt for p in attacks)


def detect_custom_entities(txt):
    res = []

    for key, pat in patterns.items():
        matches = re.findall(pat, txt)

        for m in matches:
            if not m:
                continue

            if key in ["API_KEY", "CREDIT"]:
                sc = min(0.95, 0.5 + len(m) / 30)
            elif key in ["ID", "EMP_ID", "PHONE"]:
                sc = min(0.95, 0.5 + len(m) / 25)
            else:
                sc = min(0.95, 0.5 + len(m) / 30)

            res.append({
                "entity_type": key,
                "value": m,
                "score": sc
            })

    return res


@app.post("/process")
def process(data: InputData):
    msg = data.user_input or ""
    t0 = time.time()

    # step 1 - check for attacks
    atck = detect_injection(msg)

    # step 2 - presidio analysis
    try:
        pres_results = analyzer.analyze(text=msg, language="en")
    except Exception as e:
        print("presidio broke:", e)
        pres_results = []

    # step 3 - filter presidio results
    clean_pres = []
    for r in pres_results:
        try:
            entity_text = msg[r.start:r.end]
            if (
                entity_text
                and r.entity_type != "EMAIL_ADDRESS"
                and r.score >= THRESHOLD
            ):
                clean_pres.append({
                    "entity_type": r.entity_type,
                    "value": entity_text,
                    "score": r.score
                })
        except Exception as e:
            print("skipping bad entity:", e)

    # step 4 - custom entity detection
    cust = detect_custom_entities(msg)

    # step 5 - merge both results
    all_sens = clean_pres.copy()
    for c in cust:
        if c not in all_sens:
            all_sens.append(c)

    # debug prints
    print(f"\nthreshold = {THRESHOLD}")
    for e in clean_pres:
        print(f"[presidio] {e['entity_type']} | {e['value']} | score: {e.get('score', 1.0):.2f}")
    for e in cust:
        print(f"[custom]   {e['entity_type']} | {e['value']} | score: {e.get('score', 1.0):.2f}")

    # step 6 - policy decision
    n = len(all_sens)
    out = msg
    dec = "ALLOW"

    try:
        if atck:
            dec = "BLOCK"
            out = "Request blocked due to security policy"

        elif all_sens:
            for e in all_sens:
                out = out.replace(e["value"], f"<{e['entity_type']}>")
            dec = "BLOCK" if n >= 2 else "MASK"

        else:
            dec = "ALLOW"

    except Exception as e:
        print("masking failed:", e)
        dec = "ALLOW"
        out = msg

    t1 = time.time()
    print(f"decision={dec} | entities={n} | latency={t1-t0:.4f}s")

    return {
        "input": msg,
        "decision": dec,
        "output": out,
        "latency": t1 - t0
    }
