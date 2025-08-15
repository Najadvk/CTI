document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("search-form");
  const input = document.getElementById("ioc");
  const resultDiv = document.getElementById("results");
  const detectedTypeDiv = document.getElementById("detected-type");

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

    // Initialize table with loading placeholders
    let tableHTML = `<table border="1" cellpadding="5" cellspacing="0">
      <thead>
        <tr><th>Source</th><th>Status</th><th>Details</th></tr>
      </thead>
      <tbody>`;
    sources[type].forEach(src => {
      tableHTML += `<tr id="row-${src}">
        <td>${src}</td>
        <td>Loading...</td>
        <td>-</td>
      </tr>`;
    });
    tableHTML += "</tbody></table>";
    resultDiv.innerHTML = tableHTML;

    // Fetch from all sources in parallel
    sources[type].forEach(async (source) => {
      try {
        const res = await fetch(`/.netlify/functions/lookup-${source}?q=${encodeURIComponent(ioc)}`);
        let data;
        if (res.ok) {
          data = await res.json();
        } else {
          data = { error: `HTTP ${res.status}` };
        }

        const row = document.getElementById(`row-${source}`);
        if (!row) return;

        // Map returned data to user-friendly display
        if (data.error) {
          row.cells[1].textContent = "Error";
          row.cells[2].textContent = data.error;
        } else if (data.status) {
          row.cells[1].textContent = data.status;
          row.cells[2].textContent = data.details || JSON.stringify(data);
        } else {
          // Fallback for unknown structure
          row.cells[1].textContent = "OK";
          row.cells[2].textContent = JSON.stringify(data);
        }

      } catch (err) {
        const row = document.getElementById(`row-${source}`);
        if (row) {
          row.cells[1].textContent = "Error";
          row.cells[2].textContent = err.message;
        }
      }
    });
  });

  function detectIOC(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(ioc)) return "hash";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return "domain";
    return null;
  }
});
