async function loadThreatFeed() {
  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    const result = await res.json();

    const feedDiv = document.getElementById("feed");
    feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2>";

    if (result.type === "feed" && result.feed && result.feed.data) {
      const list = document.createElement("ul");

      result.feed.data.forEach(item => {
        const li = document.createElement("li");
        li.textContent = `${item.ipAddress} | Score: ${item.abuseConfidenceScore} | Country: ${item.countryCode} | ISP: ${item.isp || "N/A"}`;
        list.appendChild(li);
      });

      feedDiv.appendChild(list);
    } else {
      feedDiv.innerHTML += "<p>No feed data available.</p>";
    }
  } catch (err) {
    document.getElementById("feed").innerHTML = `<p>Error: ${err.message}</p>`;
  }
}

async function searchIP() {
  const ip = document.getElementById("searchInput").value.trim();
  if (!ip) return;

  try {
    const res = await fetch(`/.netlify/functions/fetch-threats?ip=${ip}`);
    const result = await res.json();

    const searchDiv = document.getElementById("searchResult");
    searchDiv.innerHTML = "<h2>Search Result</h2>";

    if (result.type === "lookup" && result.data && result.data.data) {
      const d = result.data.data;
      searchDiv.innerHTML += `
        <p><strong>IP:</strong> ${d.ipAddress}</p>
        <p><strong>Abuse Score:</strong> ${d.abuseConfidenceScore}</p>
        <p><strong>Country:</strong> ${d.countryCode}</p>
        <p><strong>ISP:</strong> ${d.isp || "N/A"}</p>
        <p><strong>Domain:</strong> ${d.domain || "N/A"}</p>
      `;
    } else {
      searchDiv.innerHTML += "<p>No results found.</p>";
    }
  } catch (err) {
    document.getElementById("searchResult").innerHTML = `<p>Error: ${err.message}</p>`;
  }
}

// Load feed on page load
document.addEventListener("DOMContentLoaded", loadThreatFeed);
