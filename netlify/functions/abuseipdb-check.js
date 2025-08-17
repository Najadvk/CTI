// /.netlify/functions/abuseipdb-check.js
import fetch from "node-fetch";

export async function handler(event) {
  try {
    const { ip } = event.queryStringParameters;

    if (!ip) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing 'ip' query parameter." }),
      };
    }

    // AbuseIPDB API Key (keep in Netlify env variable, not hardcoded!)
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "AbuseIPDB API key not configured." }),
      };
    }

    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        method: "GET",
        headers: {
          Key: apiKey,
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      return {
        statusCode: response.status,
        body: JSON.stringify({ error: `AbuseIPDB error: ${response.status}` }),
      };
    }

    const data = await response.json();

    return {
      statusCode: 200,
      body: JSON.stringify(data),
    };
  } catch (err) {
    console.error("Proxy error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal server error", details: err.message }),
    };
  }
}
