# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from providers import virustotal, abuseipdb, otx, shodan, greynoise, urlhaus, malwarebazaar, mx_toolbox, whois_dns, hibp

app = FastAPI(title="Cloud CTI Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/lookup")
async def lookup(query: str):
    results = {}
    results['virustotal'] = virustotal.lookup(query)
    results['abuseipdb'] = abuseipdb.lookup(query)
    results['otx'] = otx.lookup(query)
    results['shodan'] = shodan.lookup(query)
    results['greynoise'] = greynoise.lookup(query)
    results['urlhaus'] = urlhaus.lookup(query)
    results['malwarebazaar'] = malwarebazaar.lookup(query)
    results['mx_toolbox'] = mx_toolbox.lookup(query)
    results['whois_dns'] = whois_dns.lookup(query)
    results['hibp'] = hibp.lookup(query)
    return results
