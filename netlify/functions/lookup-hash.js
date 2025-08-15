export async function handler(event) {
  const hash = event.queryStringParameters.q;
  let result = {};

  // MalwareBazaar public search
  const mbRes = await fetch(`https://mb-api.abuse.ch/api/v1/`, {
    method: "POST",
    body: new URLSearchParams({ query: "get_info", hash: hash })
  });
  result.malwareBazaar = await mbRes.json();

  // Optional VirusTotal
  const vtKey = process.env.VT_API_KEY;
  if (vtKey) {
    const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": vtKey }
    });
    result.virusTotal = await vtRes.json();
  }

  return {
    statusCode: 200,
    body: JSON.stringify(result)
  };
}
