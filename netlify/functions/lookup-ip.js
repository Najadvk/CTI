export async function handler(event) {
  const ip = event.queryStringParameters.q;
  let result = {};

  // Free data
  const ipRes = await fetch(`http://ip-api.com/json/${ip}`);
  result.freeData = await ipRes.json();

  // Optional VirusTotal
  const vtKey = process.env.VT_API_KEY;
  if (vtKey) {
    const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": vtKey }
    });
    result.virusTotal = await vtRes.json();
  }

  return {
    statusCode: 200,
    body: JSON.stringify(result)
  };
}
