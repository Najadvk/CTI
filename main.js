// main.js

// ----------------------
// Load Malicious Feed
// ----------------------
async function loadMaliciousFeed() {
  const feedDiv = document.getElementById("feed");
  feedDiv.innerHTML = "<p>Loading malicious feed...</p>";

  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    const data = await res.json();

    if (!data.feed) {
      feedDiv.innerHTML = "<p style='color:red;'>Failed to load threat feed.</p>";
      return;
    }

    let html = "";

    // Malicious IPs
    html += `<h4>IPs (${Object.keys(data.feed.ips).length})</h4><ul>`;
    Object.values(data.feed.ips).forEach(ip => {
      html += `<li>${ip.indicator} (${ip.source})</li>`;
    });
    html += `</ul>`;

    // Malicious Domains
    html += `<h4>Domains (${Object.keys(data.feed.domains).length})</h4><ul>`;
    Object.values(data.feed.domains).forEach(d => {
      html += `<li>${d.indicator} (${d.source})</li>`;
    });
    html += `</ul>`;

    // Malicious Hashes
    html += `<h4>Hashes (${Object.keys(data.feed.hashes).length})</h4><ul>`;
    Object.values(data.feed.hashes).forEach(h => {
      html += `<li>${h.indicator} (${h.source})</li>`;
    });
    html += `</ul>`;

    feedDiv.innerHTML = html;

  } catch (err) {
    feedDiv.innerHTML = `<p style='color:red;'>Error loading feed: ${err.message}</p>`;
  }
}

// ----------------------
// AbuseIPDB Search
// ----------------------
document.getElementById("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const ioc = document.getElementById("ioc").value.trim();
  if (!ioc) return;

  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "<p>Searching AbuseIPDB...</p>";

  try {
    // Call Netlify function with AbuseIPDB proxy
    const res = await fetch(`/.netlify/functions/fetch-threats?query=${ioc}`);
    const data = await res.json();

    if (data.error) {
      resultsDiv.innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
      return;
    }

    // AbuseIPDB response format
    const d = data.data;
    resultsDiv.innerHTML = `
      <h3>Results for ${d.ipAddress}</h3>
      <p><strong>Abuse Confidence Score:</strong> ${d.abuseConfidenceScore}</p>
      <p><strong>Total Reports:</strong> ${d.totalReports}</p>
      <p><strong>Last Reported At:</strong> ${d.lastReportedAt || "Never"}</p>
      <p><strong>Usage Type:</strong> ${d.usageType || "Unknown"}</p>
      <p><strong>ISP:</strong> ${d.isp || "Unknown"}</p>
      <p><strong>Country:</strong> ${d.countryCode || "Unknown"}</p>
    `;
  } catch (err) {
    resultsDiv.innerHTML = `<p style="color:red;">${err.message}</p>`;
  }
});

// ----------------------
// Initialize
// ----------------------
document.addEventListener("DOMContentLoaded", loadMaliciousFeed);
