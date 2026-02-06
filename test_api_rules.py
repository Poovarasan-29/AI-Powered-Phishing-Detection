import requests
import json

def test_analyze(url):
    print(f"\nTesting URL: {url}")
    try:
        response = requests.post("http://127.0.0.1:5000/analyze", 
                                json={"url": url},
                                timeout=5)
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test Tranco hit
    test_analyze("https://google.com")
    
    # Test unknown URL (should go to ML)
    test_analyze("https://some-unknown-site-123.com")
