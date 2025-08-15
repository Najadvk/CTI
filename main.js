async function loadThreatFeed() {
  const feedDiv = document.getElementById("feed");
  feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2><p>Loading...</p>";

  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    const result = await res.json();

    feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2>";

    if (result.type === "feed" && result.feed && result.feed.data) {
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      thead.innerHTML = "<tr><th>IP Address</th><th>Abuse Score</th><th>Last Reported</th></tr>";
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      result.feed.data.forEach(item => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${item.ipAddress}</td>
          <td class="${item.abuseConfidenceScore >= 50 ? 'status-malicious' : 'status-clean'}">${item.abuseConfidenceScore}</td>
          <td>${item.lastReportedAt || "N/A"}</td>
        `;
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      feedDiv.appendChild(table);
    } else {
      feedDiv.innerHTML += "<p>No feed data available.</p>";
    }
  } catch (err) {
    feedDiv.innerHTML = `<p>Error: ${err.message}</p>`;
  }
}

async function searchIP() {
  const ip = document.getElementById("searchInput").value.trim();
  const searchDiv = document.getElementById("searchResult");

  // Basic IP validation (IPv4 or IPv6)
  const ipRegex = /^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/;
  if (!ip || !ipRegex.test(ip)) {
    searchDiv.innerHTML = "<h2>Search Result</h2><p>Please enter a valid IP address.</p>";
    return;
  }

  searchDiv.innerHTML = "<h2>Search Result</h2><p>Loading...</p>";

  try {
    const res = await fetch(`/.netlify/functions/fetch-threats?ip=${encodeURIComponent(ip)}`);
    const result = await res.json();

    searchDiv.innerHTML = "<h2>Search Result</h2>";

    if (result.type === "lookup" && result.data && result.data.data) {
      const d = result.data.data;
      const statusClass = d.abuseConfidenceScore >= 50 ? 'status-malicious' : 'status-clean';
      searchDiv.innerHTML += `
        <table>
          <tr><th>IP</th><td>${d.ipAddress}</td></tr>
          <tr><th>Abuse Score</th><td class="${statusClass}">${d.abuseConfidenceScore}</td></tr>
          <tr><th>Country</th><td>${d.countryCode || "N/A"}</td></tr>
          <tr><th>ISP</th><td>${d.isp || "N/A"}</td></tr>
          <tr><th>Domain</th><td>${d.domain || "N/A"}</td></tr>
          <tr><th>Last Reported</th><td>${d.lastReportedAt || "N/A"}</td></tr>
        </table>
      `;
    } else {
      searchDiv.innerHTML += "<p>No results found.</p>";
    }
  } catch (err) {
    searchDiv.innerHTML = `<p>Error: ${err.message}</p>`;
  }
}

document.addEventListener("DOMContentLoaded", loadThreatFeed);
