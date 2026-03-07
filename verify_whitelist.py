
from src.features.rule_engine import RuleEngine
import tldextract

engine = RuleEngine()
urls = ["https://bit.ly/3wiNgJU", "https://www.intermatico.com/"]

for url in urls:
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}".lower()
    in_whitelist = domain in engine.whitelist
    print(f"URL: {url}")
    print(f"Domain: {domain}")
    print(f"In Whitelist: {in_whitelist}")
    print(f"Rule Engine Check: {engine.check_url(url)}")
    print("-" * 20)
