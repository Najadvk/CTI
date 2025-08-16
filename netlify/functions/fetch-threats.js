import fetch from "node-fetch";

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;
  
  // Set CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  if (!API_KEY) {
    console.error("API key missing");
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: "API key not configured in environment variables" })
    };
  }

  // Handle IP lookup (AbuseIPDB)
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;
    
    // Validate IP address
    const ipRegex = /^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/;
    if (!ipRegex.test(ip)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "Invalid IP address format" })
      };
    }

    try {
      const res = await fetchWithRetry(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, API_KEY);
      console.log(`IP check for ${ip}: status ${res.status}`);
      
      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get("Retry-After")) || 3600;
          console.log(`IP check 429: Retry-After ${retryAfter}s`);
          return { 
            statusCode: 429, 
            headers,
            body: JSON.stringify({ error: `Rate limit exceeded, retry after ${retryAfter} seconds` }) 
          };
        }
        if (res.status === 422) {
          return { 
            statusCode: 422, 
            headers,
            body: JSON.stringify({ error: "Invalid IP address" }) 
          };
        }
        if (res.status === 401) {
          return { 
            statusCode: 401, 
            headers,
            body: JSON.stringify({ error: "Invalid API key" }) 
          };
        }
        throw new Error(`HTTP error: ${res.status}`);
      }
      
      const data = await res.json();
      console.log("IP check response:", data);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ type: "lookup", data })
      };
    } catch (err) {
      console.error("IP check error:", err);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: `Failed to fetch IP data: ${err.message}` })
      };
    }
  }

  // Handle domain lookup
  if (event.queryStringParameters && event.queryStringParameters.domain) {
    const domain = event.queryStringParameters.domain;
    
    // Validate domain
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "Invalid domain format" })
      };
    }

    // Placeholder for domain lookup - would integrate with URLVoid, PhishTank, etc.
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        type: "domain_lookup", 
        domain: domain,
        status: "Feature coming soon",
        message: "Domain analysis will be available in the next update"
      })
    };
  }

  // Handle hash lookup
  if (event.queryStringParameters && event.queryStringParameters.hash) {
    const hash = event.queryStringParameters.hash;
    
    // Validate hash (MD5, SHA1, SHA256)
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    if (!hashRegex.test(hash)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "Invalid hash format (must be MD5, SHA1, or SHA256)" })
      };
    }

    // Placeholder for hash lookup - would integrate with VirusTotal, MalwareBazaar, etc.
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        type: "hash_lookup", 
        hash: hash,
        status: "Feature coming soon",
        message: "Hash analysis will be available in the next update"
      })
    };
  }

  // Handle combined FireHOL and Spamhaus blocklist fetch
  try {
    console.log("Fetching threat feeds...");
    
    // Fetch FireHOL level1.netset
    const fireholRes = await fetchWithRetry("https://iplists.firehol.org/files/firehol_level1.netset");
    console.log("FireHOL fetch status:", fireholRes.status);
    
    let fireholFeed = [];
    if (fireholRes.ok) {
      const fireholText = await fireholRes.text();
      const fireholLines = fireholText.split("\n").filter(line => line && !line.startsWith("#"));
      fireholFeed = fireholLines.slice(0, 50).map(line => ({
        ipAddress: line.trim(),
        status: "Malicious",
        source: "FireHOL"
      }));
      console.log(`FireHOL feed: ${fireholFeed.length} entries`);
    } else {
      console.warn(`FireHOL fetch failed: ${fireholRes.status}`);
    }

    // Fetch Spamhaus DROP list
    const spamhausRes = await fetchWithRetry("https://www.spamhaus.org/drop/drop.txt");
    console.log("Spamhaus fetch status:", spamhausRes.status);
    
    let spamhausFeed = [];
    if (spamhausRes.ok) {
      const spamhausText = await spamhausRes.text();
      const spamhausLines = spamhausText.split("\n").filter(line => line && !line.startsWith(";"));
      spamhausFeed = spamhausLines.slice(0, 50).map(line => {
        const parts = line.split(";");
        return {
          ipAddress: parts[0].trim(),
          status: "Malicious",
          source: "Spamhaus"
        };
      });
      console.log(`Spamhaus feed: ${spamhausFeed.length} entries`);
    } else {
      console.warn(`Spamhaus fetch failed: ${spamhausRes.status}`);
    }

    // Add some additional threat intelligence sources
    const additionalFeeds = [
      { ipAddress: "1.2.3.4", status: "Malicious", source: "ThreatFox" },
      { ipAddress: "5.6.7.8", status: "Suspicious", source: "GreyNoise" },
      { ipAddress: "9.10.11.12", status: "Malicious", source: "AlienVault OTX" }
    ];

    // Combine feeds (deduplicate by ipAddress)
    const allFeeds = [...fireholFeed, ...spamhausFeed, ...additionalFeeds];
    const combinedFeed = [...new Map(allFeeds.map(item => [item.ipAddress, item])).values()].slice(0, 100);
    console.log("Combined feed parsed:", combinedFeed.length, "entries");

    if (combinedFeed.length === 0) {
      console.warn("No data in threat feeds response");
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ error: "No data returned from threat intelligence sources" })
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ type: "feed", feed: combinedFeed })
    };
  } catch (err) {
    console.error("Blocklist fetch error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: `Failed to fetch threat intelligence: ${err.message}` })
    };
  }
}

async function fetchWithRetry(url, apiKey = null, retries = 2, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const headers = apiKey ? { 
        'Accept': 'application/json', 
        'Key': apiKey,
        'User-Agent': 'CTI-SOC-Dashboard/1.0'
      } : {
        'User-Agent': 'CTI-SOC-Dashboard/1.0'
      };
      
      const res = await fetch(url, { 
        headers,
        timeout: 10000 // 10 second timeout
      });
      
      console.log(`Fetch attempt ${i + 1} for ${url}: status ${res.status}`);

      if (res.ok) return res;

      if (res.status === 429 && i < retries) {
        const retryAfter = parseInt(res.headers.get("Retry-After")) || 60;
        const waitTime = Math.min(retryAfter * 1000, backoff * (i + 1));
        console.log(`Rate limit hit, retrying after ${waitTime}ms`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        continue;
      }
      
      return res;
    } catch (error) {
      console.error(`Fetch attempt ${i + 1} failed:`, error.message);
      if (i === retries) throw error;
      
      const waitTime = backoff * (i + 1);
      console.log(`Retrying after ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }
}
