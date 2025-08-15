document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

  // Define sources for each IOC type
  const sources = {
    ip: ["abuseipdb", "virustotal", "talos"],
    domain: ["virustotal", "talos"],
    hash: ["virustotal"]
  };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();

    if (!ioc) {
      resultDiv.innerHTML = "<p>Please enter an IOC.</p>";
      detectedTypeDiv.textContent = "";
      return;
    }

    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";

    if (!type) {
      resultDiv.innerHTML = "<p>Unable to detect IOC type.</p>";
      return;
    }

    resultDiv.innerHTML = "<p>Loading...</p>";

    try {
      // Fetch from all sources in parallel
      const fetchPromises = sources[type].map(source =>
        fetch(`/.netlify/functions/lookup-${source}?q=${encodeURIComponent(ioc)}`)
          .then(res => res.ok ? res.json() : { error: `HTTP ${res.status}` })
          .then(data => ({ source, value: data }))
          .catch(err => ({ source, value: `Error: ${err.message}` }))
      );

      const results = await Promise.all(fetchPromises);
      renderTable(results);
    } catch (err) {
      console.error(err);
      resultDiv.innerHTML = `<p>Error: ${err.message}</p>`;
    }
  });

  function detectIOC(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    return null;
  }

  function renderTable(results) {
    if (!results || results.length === 0) {
      resultDiv.innerHTML = "<p>No data found.</p>";
      return;
    }

    let table = `<table border="1" cellpadding="5" cellspacing="0">
      <thead>
        <tr>
          <th>Source</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>`;

    results.forEach(r => {
      table += `<tr>
        <td>${r.source}</td>
        <td>${typeof r.value === "object" ? JSON.stringify(r.value, null, 2) : r.value}</td>
      </tr>`;
    });

    table += "</tbody></table>";
    resultDiv.innerHTML = table;
  }
});
