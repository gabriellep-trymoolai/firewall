import requests

BASE_URL = "https://firewall-9n0t.onrender.com"  # render is used, add your backend url

def test_endpoint(endpoint: str, prompt: str):
    url = f"{BASE_URL}{endpoint}"
    payload = {"prompt": prompt}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"✅ {endpoint}: PASSED ({response.json()})")
        elif response.status_code == 403:
            print(f"⛔ {endpoint}: BLOCKED ({response.json()})")
        else:
            print(f"❌ {endpoint}: Status {response.status_code} ({response.json()})")
    except Exception as e:
        print(f"❗ {endpoint}: Exception - {e}")

if __name__ == "__main__":
    print("=== Simple Firewall API Tester ===\n")
    prompt = input("Enter your test prompt: ")

    endpoints = [
        "/test/allowlist",
        "/test/blocklist",
        "/test/pii",
        "/test/secrets",
        "/test/promptinjection",
        "/process_prompt"
    ]

    for endpoint in endpoints:
        test_endpoint(endpoint, prompt)

    print("\n✅ Finished testing all routes.")