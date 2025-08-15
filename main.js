document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM fully loaded");

  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeSpan = document.getElementById("detected-type");
  const alertsDiv = document.getElementById("alerts");

  if (!form || !input || !resultDiv || !detectedTypeSpan) {
    console.error("Some required DOM elements are missing.");
    if (resultDiv) resultDiv.innerHTML = "<p>Error: Missing HTML elements.</p>";
    return;
  }

  function detectIOC(ioc) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc))
      return "ip";
    if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    return "unknown";
  }

  async function fetchIPData(ip) {
    try {
      const res = await fetch(`https://ipapi.co/${ip}/json/`);
      if (!res.ok) throw new Error(res.status);
      return await res.json();
    } catch (err) {
      console.error("Failed to fetch IP data:", err);
      return { error: err.message };
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    if (!ioc) {
      resultDiv.innerHTML = "<p>Please enter an IP, domain, or hash.</p>";
      detectedTypeSpan.innerText = "unknown";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeSpan.innerText = type;

    resultDiv.innerHTML = "<p>Fetching data...</p>";
    alertsDiv.innerHTML = "";

    if (type === "ip") {
      const data = await fetchIPData(ioc);
      if (data.error) {
        resultDiv.innerHTML = `<p>Error fetching IP info: ${data.error}</p>`;
      } else {
        resultDiv.innerHTML = `
          <h3>IP Information</h3>
          <ul>
            <li>IP: ${data.ip || ioc}</li>
            <li>City: ${data.city || "N/A"}</li>
            <li>Region: ${data.region || "N/A"}</li>
            <li>Country: ${data.country_name || "N/A"}</li>
            <li>ASN: ${data.asn || "N/A"}</li>
            <li>Org: ${data.org || "N/A"}</li>
          </ul>
        `;
      }
    } else if (type === "domain") {
      resultDiv.innerHTML = `<p>Domain lookup is not implemented yet.</p>`;
    } else if (type === "hash") {
      resultDiv.innerHTML = `<p>Hash lookup is not implemented yet.</p>`;
    } else {
      resultDiv.innerHTML = "<p>Invalid input format.</p>";
    }
  });
});
