import requests

# Make sure your FastAPI server is running at this URL
url = "http://127.0.0.1:8000/process"

try:
    user_input = input("Enter text to process: ").strip()
    if not user_input:
        print("No input provided, exiting...")
        exit()

    payload = {"user_input": user_input}

    response = requests.post(url, json=payload)

    if response.status_code == 200:
        # Try to decode JSON safely
        try:
            data = response.json()
            print("\nResponse from server:")
            print(f"Input: {data.get('input')}")
            print(f"Decision: {data.get('decision')}")
            print(f"Output: {data.get('output')}")
            print(f"Latency: {data.get('latency'):.4f} seconds")
        except Exception as e:
            print("[ERROR] Failed to decode JSON:", e)
            print("Raw response:", response.text)
    else:
        print(f"Server returned status code {response.status_code}")
        print("Raw response:", response.text)

except requests.exceptions.ConnectionError:
    print("[ERROR] Could not connect to server. Is FastAPI running?")

except Exception as e:
    print("[ERROR] Unexpected error:", e)

input("\nPress Enter to exit...")
