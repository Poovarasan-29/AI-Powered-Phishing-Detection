from src.features.rule_engine import RuleEngine

engine = RuleEngine()

# Test various hosting providers
test_urls = [
    "https://startsstarted.ghost.io", # Was passing as Safe, should now be Unknown (0)
    "https://my-repo.github.io", # Subdomain hosted
    "https://google.com" # Safe
]

print("--- Testing Shared Provider Logic ---")
for url in test_urls:
    res = engine.check_url(url)
    status = "SAFE (Whitelist)" if res == 1 else "PHISHING (Blacklist)" if res == -1 else "UNKNOWN (Send to AI)"
    print(f"URL: {url:<35} | Assessment: {status}")
