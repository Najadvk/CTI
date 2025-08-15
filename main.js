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

  // Helper to map status to color
  function getStatusColor(status) {
    status = String(status).toLowerCase();
    if (status.includes("malicious") || status.includes("bad") || status === "error") return "red";
    if (status.includes("suspicious") || status.includes("unknown")) return "orange";
    if (status.includes("clean") || status.includes("ok") || status === "safe") return "green";
    return "black";
  }

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
        <td style="color: gray;">Loading...</td>
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

        let statusText, detailsText;
        if (data.error) {
          statusText = "Error";
          detailsText = data.error;
        } else if (data.status) {
          statusText = data.status;
          detailsText = data.details || JSON.stringify(data);
        } else {
          statusText = "OK";
          detailsText = JSON.stringify(data);
        }

        row.cells[1].textContent = statusText;
        row.cells[1].style.color = getStatusColor(statusText);
        row.cells[2].textContent = detailsText;

      } catch (err) {
        const row = document.getElementById(`row-${source}`);
        if (row) {
          row.cells[1].textContent = "Error";
          row.cells[1].style.color = "red";
          row.cells[2].textContent = err.message;
        }
      }
    });
  });

  function detectIOC(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return "ip";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|
