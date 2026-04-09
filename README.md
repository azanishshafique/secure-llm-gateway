# secure-llm-gateway
#  Secure LLM Gateway

A security gateway for LLM applications built 
with FastAPI and Microsoft Presidio.

## Installation

pip install fastapi uvicorn presidio-analyzer 
presidio-anonymizer pydantic requests

##  Run The Server

uvicorn app:app --reload

##  Run The Client

python client.py

##  How To Test

1. Run server first
2. Run client in another terminal
3. Enter any text when prompted
4. System returns ALLOW / MASK / BLOCK

##  Files

| File | Description |
|------|-------------|
| app.py | Main FastAPI server |
| client.py | Client to send requests |

##  Requirements

- Python 3.8+
- FastAPI
- Microsoft Presidio
- Uvicorn
