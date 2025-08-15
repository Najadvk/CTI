async function loadThreatFeed(refresh = false) {
  const feedDiv = document.getElementById("feed");
  feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2><button onclick='refreshFeed()' class='btn'>Refresh Feed</button><p>Loading...</p>";

  // Check for cached feed unless refreshing
  if (!refresh) {
    const cachedFeed = localStorage.getItem("threatFeed");
    const cacheTime = localStorage.getItem("threatFeedTime");
    const cacheAge = cacheTime ? (Date.now() - parseInt(cacheTime)) / (1000 * 60 * 60) : Infinity;

    console.log("Cache age (hours):", cacheAge, "Cached feed exists:", !!cachedFeed);

    if (cachedFeed && cacheAge < 24) {
      try {
        const result = JSON.parse(cachedFeed);
        console.log("Cached feed:", result);
        if (result.type === "feed" && result.feed && result.feed.data && Array.isArray(result.feed.data)) {
          renderFeed(result, feedDiv);
          feedDiv.innerHTML += "<p>Loaded from cache (valid for 24 hours).</p>";
          return;
        } else {
          console.warn("Invalid cached feed structure");
        }
      } catch (err) {
        console.error("Failed to parse cached feed:", err);
        localStorage.removeItem("threatFeed"); // Clear corrupted cache
        localStorage.removeItem("threatFeedTime");
      }
    }
  }

  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();
    console.log("Fetch response:", result);

    feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2><button onclick='refreshFeed()' class='btn'>Refresh Feed</button>";

    if (result.error) {
      feedDiv.innerHTML += `<p>Error: ${result.error}. Using cached data if available.</p>`;
      if (!refresh) {
        const cachedFeed = localStorage.getItem("threatFeed");
        if (cachedFeed) {
          try {
            const cachedResult = JSON.parse(cachedFeed);
            if (cachedResult.type === "feed" && cachedResult.feed && cachedResult.feed.data && Array.isArray(cachedResult.feed.data)) {
              renderFeed(cachedResult, feedDiv);
              feedDiv.innerHTML += "<p>Showing cached data due to rate limit.</p>";
            } else {
              renderStaticFeed(feedDiv);
              feedDiv.innerHTML += "<p>No valid cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
            }
          } catch (err) {
            renderStaticFeed(feedDiv);
            feedDiv.innerHTML += "<p>No valid cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
            console.error("Failed to parse cached feed on error:", err);
            localStorage.removeItem("threatFeed"); // Clear corrupted cache
            localStorage.removeItem("threatFeedTime");
          }
        } else {
          renderStaticFeed(feedDiv);
          feedDiv.innerHTML += "<p>No cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
        }
      }
      return;
    }

    if (result.type === "feed" && result.feed && result.feed.data && Array.isArray(result.feed.data)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      console.log("Cached new feed:", result);
      renderFeed(result, feedDiv);
    } else {
      feedDiv.innerHTML += `<p>No feed data available: ${result.error || "Unexpected response format"}</p>`;
      renderStaticFeed(feedDiv);
    }
  } catch (err) {
    feedDiv.innerHTML = `<h2>Latest Malicious IPs</h2><button onclick='refreshFeed()' class='btn'>Refresh Feed</button><p>Error: ${err.message}. Using cached data if available.</p>`;
    if (!refresh) {
      const cachedFeed = localStorage.getItem("threatFeed");
      if (cachedFeed) {
        try {
          const cachedResult = JSON.parse(cachedFeed);
          if (cachedResult.type === "feed" && cachedResult.feed && cachedResult.feed.data && Array.isArray(cachedResult.feed.data)) {
            renderFeed(cachedResult, feedDiv);
            feedDiv.innerHTML += "<p>Showing cached data due to error.</p>";
          } else {
            renderStaticFeed(feedDiv);
            feedDiv.innerHTML += "<p>No valid cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
          }
        } catch (err) {
          renderStaticFeed(feedDiv);
          feedDiv.innerHTML += "<p>No valid cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
          console.error("Failed to parse cached feed on error:", err);
          localStorage.removeItem("threatFeed"); // Clear corrupted cache
          localStorage.removeItem("threatFeedTime");
        }
      } else {
        renderStaticFeed(feedDiv);
        feedDiv.innerHTML += "<p>No cached data. Rate limit exceeded (limited to 5 checks/day). Try again after 1:00 AM BST (midnight UTC, August 16, 2025) or upgrade your plan at <a href='https://www.abuseipdb.com/pricing'>https://www.abuseipdb.com/pricing</a>.</p>";
      }
    }
    console.error("Feed fetch error:", err);
  }
}

function renderFeed(result, feedDiv) {
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
}

function renderStaticFeed(feedDiv) {
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>IP Address</th><th>Abuse Score</th><th>Last Reported</th></tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  const sampleData = [
    { ipAddress: "192.168.1.1", abuseConfidenceScore: 75, lastReportedAt: "2025-08-15T12:00:00Z" },
    { ipAddress: "10.0.0.1", abuseConfidenceScore: 90, lastReportedAt: "2025-08-14T10:00:00Z" }
  ];
  sampleData.forEach(item => {
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
  feedDiv.innerHTML += "<p>Showing sample data due to API unavailability.</p>";
}

async function refreshFeed() {
  localStorage.removeItem("threatFeed");
  localStorage.removeItem("threatFeedTime");
  console.log("Cache cleared, refreshing feed...");
  await loadThreatFeed(true);
}

async function searchIP() {
  const ip = document.getElementById("searchInput").value.trim();
  const searchDiv = document.getElementById("searchResult");

  const ipRegex = /^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$/;
  if (!ip || !ipRegex.test(ip)) {
    searchDiv.innerHTML = "<h2>Search Result</h2><p>Please enter a valid IP address.</p>";
    return;
  }

  searchDiv.innerHTML = "<h2>Search Result</h2><p>Loading...</p>";

  try {
    const res = await fetch(`/.netlify/functions/fetch-threats?ip=${encodeURIComponent(ip)}`);
    console.log("Search response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();
    console.log("Search response:", result);

    searchDiv.innerHTML = "<h2>Search Result</h2>";

    if (result.error) {
      searchDiv.innerHTML += `<p>Error: ${result.error}</p>`;
      return;
    }

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
      searchDiv.innerHTML += `<p>No results found: ${result.error || "Unexpected response format"}</p>`;
    }
  } catch (err) {
    searchDiv.innerHTML = `<p>Error: ${err.message}</p>`;
    console.error("Search error:", err);
  }
}

document.addEventListener("DOMContentLoaded", () => loadThreatFeed(false));
