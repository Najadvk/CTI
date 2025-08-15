# CTI Cloud-Ready Starter

# Backend (FastAPI) + Frontend (React + Tailwind) fully wired to OSINT providers.

# Structure:
# backend/ -> FastAPI API
# frontend/ -> React + Tailwind app

# Ready to push to GitHub, deploy backend to Render, frontend to Netlify.

# .env.example in backend includes all API key placeholders:
# VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY, MXTOOLBOX_API_KEY, HIBP_API_KEY



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
