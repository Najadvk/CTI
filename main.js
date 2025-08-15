document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ioc = input.value.trim();
    const type = detectIOC(ioc);
    detectedTypeDiv.textContent = type || "unknown";

    if (!type) {
      resultDiv.innerHTML = "<p>Unable to detect IOC type.</p>";
      return;
    }

    try {
      const url = `/.netlify/functions/lookup-${type}?q=${encodeURIComponent(ioc)}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderTable(data);
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

  function renderTable(data) {
    if (!data || Object.keys(data).length === 0) {
      resultDiv.innerHTML = "<p>No data found.</p>";
      return;
    }

    // Build table headers
    let table = `<table border="1" cellpadding="5" cellspacing="0">
      <thead>
        <tr>
          <th>Source</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>`;

    for (const [source, value] of Object.entries(data)) {
      table += `<tr>
        <td>${source}</td>
        <td>${value}</td>
      </tr>`;
    }

    table += "</tbody></table>";
    resultDiv.innerHTML = table;
  }
});
