import fetch from "node-fetch";

let cachedFeed = null;
let lastFetchTime = null;

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;

  // If search query param is passed → lookup IP
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;

    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
        headers: {
          Accept: "application/json",
          Key: API_KEY
        }
      });

      if (!res.ok) throw new Error(`HTTP error! ${res.status}`);
      const data = await res.json();

      return {
        statusCode: 200,
        body: JSON.stringify({ type: "lookup", data })
      };
    } catch (err) {
      return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
    }
  }

  // Otherwise → return cached feed
  try {
    const now = Date.now();

    // If cache is older than 24 hours or empty → refresh
    if (!cachedFeed || !lastFetchTime || (now - lastFetchTime) > 24 * 60 * 60 * 1000) {
      const res = await fetch("https://api.abuseipdb.com/api/v2/blacklist", {
        headers: {
          Accept: "application/json",
          Key: API_KEY
        }
      });

      if (!res.ok) throw new Error(`HTTP error! ${res.status}`);
      const data = await res.json();

      cachedFeed = { type: "feed", feed: data };
      lastFetchTime = now;
    }

    return {
      statusCode: 200,
      body: JSON.stringify(cachedFeed)
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
}
