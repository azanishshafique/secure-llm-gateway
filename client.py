import requests

url = "http://127.0.0.1:8000/process"

try:
    user_input = input("Enter text: ").strip()
    
    if not user_input:
        print("nothing entered, bye")
        exit()

    payload = {"user_input": user_input}
    resp = requests.post(url, json=payload)

    if resp.status_code == 200:
        try:
            d = resp.json()
            print("\n--- Server Response ---")
            print("Input   :", d.get("input"))
            print("Decision:", d.get("decision"))
            print("Output  :", d.get("output"))
            print(f"Latency : {d.get('latency'):.4f}s")
        except Exception as e:
            print("json parse failed:", e)
            print(resp.text)
    else:
        print("got status:", resp.status_code)
        print(resp.text)

except requests.exceptions.ConnectionError:
    print("server not running? start FastAPI first")

except Exception as e:
    print("something broke:", e)

input("\nenter to exit...")



