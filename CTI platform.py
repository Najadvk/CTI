# CTI Cloud-Ready Starter

# Backend (FastAPI) + Frontend (React + Tailwind) fully wired to OSINT providers.

# Structure:
# backend/ -> FastAPI API
# frontend/ -> React + Tailwind app

# Ready to push to GitHub, deploy backend to Render, frontend to Netlify.

# .env.example in backend includes all API key placeholders:
# VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY, MXTOOLBOX_API_KEY, HIBP_API_KEY

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

# frontend/src/services/api.js
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL || 'https://your-render-backend.com';

export const fetchCTI = async (query) => {
    const response = await axios.get(`${API_URL}/lookup`, { params: { query } });
    return response.data;
}

# frontend/src/App.jsx
import React, { useState } from 'react';
import { fetchCTI } from './services/api';
import SearchBox from './components/SearchBox';
import ResultsTabs from './components/ResultsTabs';

export default function App() {
  const [results, setResults] = useState(null);
  const handleSearch = async (query) => {
    const data = await fetchCTI(query);
    setResults(data);
  };

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Cloud CTI Platform</h1>
      <SearchBox onSearch={handleSearch} />
      {results && <ResultsTabs results={results} />}
    </div>
  );
}
