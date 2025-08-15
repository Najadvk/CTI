export async function handler(event) {
  const domain = event.queryStringParameters.q;
  let result = {};

  // RDAP WHOIS (free)
  const rdapRes = await fetch(`https://rdap.org/domain/${domain}`);
  result.rdap = await rdapRes.json();

  // DNS records (free)
  const dnsRes = await fetch(`https://dns.google/resolve?name=${domain}`);
  result.dns = await dnsRes.json();

  // Optional VirusTotal
  const vtKey = process.env.VT_API_KEY;
  if (vtKey) {
    const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { "x-apikey": vtKey }
    });
    result.virusTotal = await vtRes.json();
  }

  return {
    statusCode: 200,
    body: JSON.stringify(result)
  };
}
