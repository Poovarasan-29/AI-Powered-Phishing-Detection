
import requests

url = "https://bit.ly/3wiNgJU"
try:
    response = requests.head(url, allow_redirects=True, timeout=10)
    print(f"URL: {url}")
    print(f"Final Destination: {response.url}")
except Exception as e:
    print(f"Error: {e}")
