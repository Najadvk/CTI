// netlify/functions/fetch-threats.js
import fetch from "node-fetch";

export async function handler(event) {
  try {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    const params = event.queryStringParameters;

    // Lookup specific IP
    if (params && params.ip) {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${params.ip}`, {
        headers: { Key: apiKey, Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`HTTP error! ${res.status}`);
      const data = await res.json();
      return { statusCode: 200, body: JSON.stringify({ type: "lookup", data }) };
    }

    // Fetch latest blacklist (feed)
    const res = await fetch("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10", {
      headers: { Key: apiKey, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`HTTP error! ${res.status}`);
    const feed = await res.json();

    return { statusCode: 200, body: JSON.stringify({ type: "feed", feed }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
}
