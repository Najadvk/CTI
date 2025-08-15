import fetch from "node-fetch";

export async function handler(event) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;

  // Handle IP lookup
  if (event.queryStringParameters && event.queryStringParameters.ip) {
    const ip = event.queryStringParameters.ip;
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
        headers: {
          Accept: "application/json",
          Key: API_KEY
        }
      });

      if (!res.ok) {
        if (res.status === 429) return { statusCode: 429, body: JSON.stringify({ error: "Rate limit exceeded, try later" }) };
        if (res.status === 422) return { statusCode: 422, body: JSON.stringify({ error: "Invalid IP address" }) };
        throw new Error(`HTTP error! ${res.status}`);
      }
      const data = await res.json();

      return {
        statusCode: 200,
        body: JSON.stringify({ type: "lookup", data })
      };
    } catch (err) {
      return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
    }
  }

  // Handle feed fetch
  try {
    const res = await fetch("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=1000", {
      headers: {
        Accept: "application/json",
        Key: API_KEY
      }
    });

    if (!res.ok) {
      if (res.status === 429) return { statusCode: 429, body: JSON.stringify({ error: "Rate limit exceeded, try later" }) };
      throw new Error(`HTTP error! ${res.status}`);
    }
    const data = await res.json();

    return {
      statusCode: 200,
      body: JSON.stringify({ type: "feed", feed: data })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
}
