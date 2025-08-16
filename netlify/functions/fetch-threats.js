import fetch from "node-fetch";

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;
  if (!API_KEY) {
    console.error("API key missing");
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "API key not configured in environment variables" })
    };
  }

  // Handle IP lookup (AbuseIPDB)
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;
    try {
      const res = await fetchWithRetry(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, API_KEY);
      console.log(`IP check for ${ip}: status ${res.status}`);
      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get("Retry-After")) || 3600;
          console.log(`IP check 429: Retry-After ${retryAfter}s`);
          return { statusCode: 429, body: JSON.stringify({ error: `Rate limit exceeded, retry after ${retryAfter} seconds` }) };
        }
        if (res.status === 422) return { statusCode: 422, body: JSON.stringify({ error: "Invalid IP address" }) };
        if (res.status === 401) return { statusCode: 401, body: JSON.stringify({ error: "Invalid API key" }) };
        throw new Error(`HTTP error: ${res.status}`);
      }
      const data = await res.json();
      console.log("IP check response:", data);

      return {
        statusCode: 200,
        body: JSON.stringify({ type: "lookup", data })
      };
    } catch (err) {
      console.error("IP check error:", err);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: `Failed to fetch IP data: ${err.message}` })
      };
    }
  }

  // Handle combined FireHOL and Spamhaus blocklist fetch
  try {
    // Fetch FireHOL level1.netset
    const fireholRes = await fetchWithRetry("https://iplists.firehol.org/files/firehol_level1.netset");
    console.log("FireHOL fetch status:", fireholRes.status);
    if (!fireholRes.ok) throw new Error(`FireHOL HTTP error: ${fireholRes.status}`);
    const fireholText = await fireholRes.text();
    const fireholLines = fireholText.split("\n").filter(line => line && !line.startsWith("#"));
    const fireholFeed = fireholLines.slice(0, 50).map(line => ({
      ipAddress: line.trim(),
      status: "Malicious",
      source: "FireHOL"
    }));

    // Fetch Spamhaus DROP list
    const spamhausRes = await fetchWithRetry("https://www.spamhaus.org/drop/drop.txt");
    console.log("Spamhaus fetch status:", spamhausRes.status);
    if (!spamhausRes.ok) throw new Error(`Spamhaus HTTP error: ${spamhausRes.status}`);
    const spamhausText = await spamhausRes.text();
    const spamhausLines = spamhausText.split("\n").filter(line => line && !line.startsWith(";"));
    const spamhausFeed = spamhausLines.slice(0, 50).map(line => ({
      ipAddress: line.split(";")[0].trim(),
      status: "Malicious",
      source: "Spamhaus"
    }));

    // Combine feeds (deduplicate by ipAddress) - Fixed variable name bug
    const combinedFeed = [...new Map([...fireholFeed, ...spamhausFeed].map(item => [item.ipAddress, item])).values()].slice(0, 100);
    console.log("Combined feed parsed:", combinedFeed.length, "entries");

    if (combinedFeed.length === 0) {
      console.warn("No data in FireHOL/Spamhaus response");
      return {
        statusCode: 200,
        body: JSON.stringify({ error: "No data returned from FireHOL/Spamhaus blocklists" })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ type: "feed", feed: combinedFeed })
    };
  } catch (err) {
    console.error("Blocklist fetch error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: `Failed to fetch FireHOL/Spamhaus blocklists: ${err.message}` })
    };
  }
}

async function fetchWithRetry(url, apiKey = null, retries = 1, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    const headers = apiKey ? { Accept: "application/json", Key: apiKey } : {};
    const res = await fetch(url, { headers });
    console.log(`Fetch attempt ${i + 1} for ${url}: status ${res.status}`);

    if (res.ok) return res;

    if (res.status === 429 && i < retries) {
      const retryAfter = parseInt(res.headers.get("Retry-After")) || 60;
      console.log(`Rate limit hit, retrying after ${backoff * (i + 1)}ms`);
      await new Promise(resolve => setTimeout(resolve, backoff * (i + 1)));
      continue;
    }
    return res;
  }
}



live

Jump to live
