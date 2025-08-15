// netlify/functions/fetch-threats.js
export async function handler(event, context) {
  try {
    const API_KEY = process.env.ABUSEIPDB_API_KEY;

    if (!API_KEY) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Missing AbuseIPDB API Key" }),
      };
    }

    const { query } = event.queryStringParameters;

    if (!query) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing query parameter (IP address)" }),
      };
    }

    // Call AbuseIPDB API
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${query}&maxAgeInDays=30`, {
      headers: {
        "Key": API_KEY,
        "Accept": "application/json",
      },
    });

    if (!res.ok) {
      return {
        statusCode: res.status,
        body: JSON.stringify({ error: `API request failed with ${res.status}` }),
      };
    }

    const data = await res.json();

    return {
      statusCode: 200,
      body: JSON.stringify(data, null, 2),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message }),
    };
  }
}
