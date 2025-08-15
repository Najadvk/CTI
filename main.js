// main.js
document.getElementById("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const ioc = document.getElementById("ioc").value.trim();
  if (!ioc) return;

  document.getElementById("results").innerHTML = "<p>Loading...</p>";

  try {
    const res = await fetch(`/.netlify/functions/fetch-threats?query=${ioc}`);
    const data = await res.json();

    if (data.error) {
      document.getElementById("results").innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
      return;
    }

    // AbuseIPDB response
    const d = data.data;
    document.getElementById("results").innerHTML = `
      <h3>Results for ${d.ipAddress}</h3>
      <p><strong>Abuse Confidence Score:</strong> ${d.abuseConfidenceScore}</p>
      <p><strong>Total Reports:</strong> ${d.totalReports}</p>
      <p><strong>Last Reported At:</strong> ${d.lastReportedAt || "Never"}</p>
      <p><strong>Usage Type:</strong> ${d.usageType || "Unknown"}</p>
      <p><strong>ISP:</strong> ${d.isp || "Unknown"}</p>
      <p><strong>Country:</strong> ${d.countryCode || "Unknown"}</p>
    `;
  } catch (err) {
    document.getElementById("results").innerHTML = `<p style="color:red;">${err.message}</p>`;
  }
});
