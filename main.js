let refreshInterval;

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
        if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
          renderFeed(result, feedDiv);
          feedDiv.innerHTML += "<p>Loaded from cache (valid for 24 hours). Auto-updates every 10 minutes.</p>";
          startAutoRefresh();
          return;
        } else {
          console.warn("Invalid cached feed structure");
          localStorage.removeItem("threatFeed"); // Clear corrupted cache
          localStorage.removeItem("threatFeedTime");
        }
      } catch (err) {
        console.error("Failed to parse cached feed:", err);
        localStorage.removeItem("threatFeed"); // Clear corrupted cache
        localStorage.removeItem("threatFeedTime");
      }
    }
    // No cache, show static feed
    renderStaticFeed(feedDiv);
    feedDiv.innerHTML += "<p>Showing sample data. Click 'Refresh Feed' to fetch latest FireHOL/Spamhaus blocklists. Auto-updates every 10 minutes.</p>";
    startAutoRefresh();
    return;
  }

  // Fetch combined blocklist on refresh
  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();
    console.log("Fetch response:", result);

    feedDiv.innerHTML = "<h2>Latest Malicious IPs</h2><button onclick='refreshFeed()' class='btn'>Refresh Feed</button>";

    if (result.error) {
      feedDiv.innerHTML += `<p>Error: ${result.error}. Using cached data if available.</p>`;
      const cachedFeed = localStorage.getItem("threatFeed");
      if (cachedFeed) {
        try {
          const cachedResult = JSON.parse(cachedFeed);
          if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
            renderFeed(cachedResult, feedDiv);
            feedDiv.innerHTML += "<p>Showing cached data due to error. Auto-updates every 10 minutes.</p>";
            startAutoRefresh();
          } else {
            renderStaticFeed(feedDiv);
            feedDiv.innerHTML += "<p>No valid cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
          }
        } catch (err) {
          renderStaticFeed(feedDiv);
          feedDiv.innerHTML += "<p>No valid cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
          console.error("Failed to parse cached feed on error:", err);
          localStorage.removeItem("threatFeed"); // Clear corrupted cache
          localStorage.removeItem("threatFeedTime");
        }
      } else {
        renderStaticFeed(feedDiv);
        feedDiv.innerHTML += "<p>No cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
      }
      return;
    }

    if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      console.log("Cached new feed:", result);
      renderFeed(result, feedDiv);
      feedDiv.innerHTML += "<p>Fetched latest FireHOL/Spamhaus blocklists. Auto-updates every 10 minutes.</p>";
      startAutoRefresh();
    } else {
      feedDiv.innerHTML += `<p>No feed data available: ${result.error || "Unexpected response format"}</p>`;
      renderStaticFeed(feedDiv);
    }
  } catch (err) {
    feedDiv.innerHTML = `<h2>Latest Malicious IPs</h2><button onclick='refreshFeed()' class='btn'>Refresh Feed</button><p>Error: ${err.message}. Using cached data if available.</p>`;
    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        const cachedResult = JSON.parse(cachedFeed);
        if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
          renderFeed(cachedResult, feedDiv);
          feedDiv.innerHTML += "<p>Showing cached data due to error. Auto-updates every 10 minutes.</p>";
          startAutoRefresh();
        } else {
          renderStaticFeed(feedDiv);
          feedDiv.innerHTML += "<p>No valid cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
        }
      } catch (err) {
        renderStaticFeed(feedDiv);
        feedDiv.innerHTML += "<p>No valid cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
        console.error("Failed to parse cached feed on error:", err);
        localStorage.removeItem("threatFeed"); // Clear corrupted cache
        localStorage.removeItem("threatFeedTime");
      }
    } else {
      renderStaticFeed(feedDiv);
      feedDiv.innerHTML += "<p>No cached data. Failed to fetch FireHOL/Spamhaus blocklists.</p>";
    }
    console.error("Feed fetch error:", err);
  }
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(() => loadThreatFeed(true), 600000); // Refresh every 10 minutes
}

function renderFeed(result, feedDiv) {
  const select = document.createElement("select");
  select.className = "feed-select";
  select.innerHTML = '<option value="">Select an IP</option>';
  result.feed.slice(0, 100).forEach(item => {
    const option = document.createElement("option");
    option.value = item.ipAddress;
    option.textContent = `${item.ipAddress} (${item.source})`;
    select.appendChild(option);
  });
  const container = document.createElement("div");
  container.className = "feed-container";
  container.appendChild(select);
  feedDiv.appendChild(container);
}

function renderStaticFeed(feedDiv) {
  const select = document.createElement("select");
  select.className = "feed-select";
  select.innerHTML = '<option value="">Select an IP</option>';
  const sampleData = [
    { ipAddress: "45.146.164.125", status: "Malicious", source: "Sample" },
    { ipAddress: "118.25.6.39", status: "Malicious", source: "Sample" },
    { ipAddress: "185.173.35.14", status: "Malicious", source: "Sample" },
    { ipAddress: "103.196.36.10", status: "Malicious", source: "Sample" }
  ];
  sampleData.forEach(item => {
    const option = document.createElement("option");
    option.value = item.ipAddress;
    option.textContent = `${item.ipAddress} (${item.source})`;
    select.appendChild(option);
  });
  const container = document.createElement("div");
  container.className = "feed-container";
  container.appendChild(select);
  feedDiv.appendChild(container);
  feedDiv.innerHTML += "<p>Showing sample data due to unavailability.</p>";
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
