import fetch from "node-fetch";

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;
  if (!API_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "API key not configured in environment variables" })
    };
  }

  // Handle IP lookup
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;
    try {
      const res = await fetchWithRetry(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, API_KEY);
      if (!res.ok) {
        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get("Retry-After")) || 3600;
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

  // Handle feed fetch
  try {
    const res = await fetchWithRetry("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=50", API_KEY);
    if (!res.ok) {
      if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get("Retry-After")) || 3600;
        return { statusCode: 429, body: JSON.stringify({ error: `Rate limit exceeded, retry after ${retryAfter} seconds` }) };
      }
      if (res.status === 401) return { statusCode: 401, body: JSON.stringify({ error: "Invalid API key" }) };
      throw new Error(`HTTP error: ${res.status}`);
    }
    const data = await res.json();
    console.log("Blacklist response:", data);

    if (!data.data || !Array.isArray(data.data)) {
      return {
        statusCode: 200,
        body: JSON.stringify({ error: "No data returned from blacklist endpoint" })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ type: "feed", feed: data })
    };
  } catch (err) {
    console.error("Blacklist fetch error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: `Failed to fetch blacklist: ${err.message}` })
    };
  }
}

async function fetchWithRetry(url, apiKey, retries = 1, backoff = 1000) {
  for (let i = 0; i <= retries; i++) {
    const res = await fetch(url, {
      headers: {
        Accept: "application/json",
        Key: apiKey
      }
    });
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
