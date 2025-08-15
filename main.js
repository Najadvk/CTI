let refreshInterval;

async function loadThreatFeed(refresh = false) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");
  const statusDiv = document.getElementById("feedStatus");

  ipFeedDiv.innerHTML = "<p>Loading...</p>";
  domainFeedDiv.innerHTML = "<p>Loading...</p>";
  hashFeedDiv.innerHTML = "<p>Loading...</p>";
  statusDiv.innerHTML = "Loading threat feeds...";

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
        if (result.type === "feed" && result.ipFeed && result.domainFeed && result.hashFeed && Array.isArray(result.ipFeed) && Array.isArray(result.domainFeed) && Array.isArray(result.hashFeed)) {
          renderFeed(result, ipFeedDiv, domainFeedDiv, hashFeedDiv);
          statusDiv.innerHTML = "Loaded from cache (valid for 24 hours). Auto-updates every 10 minutes.";
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
    renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
    statusDiv.innerHTML = "Showing sample data. Click 'Refresh Feeds' to fetch latest FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds. Auto-updates every 10 minutes.";
    startAutoRefresh();
    return;
  }

  // Fetch combined blocklists on refresh
  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();
    console.log("Fetch response:", result);

    statusDiv.innerHTML = "";

    if (result.error) {
      statusDiv.innerHTML = `Error: ${result.error}. Using cached data if available.`;
      const cachedFeed = localStorage.getItem("threatFeed");
      if (cachedFeed) {
        try {
          const cachedResult = JSON.parse(cachedFeed);
          if (cachedResult.type === "feed" && cachedResult.ipFeed && cachedResult.domainFeed && cachedResult.hashFeed && Array.isArray(cachedResult.ipFeed) && Array.isArray(cachedResult.domainFeed) && Array.isArray(cachedResult.hashFeed)) {
            renderFeed(cachedResult, ipFeedDiv, domainFeedDiv, hashFeedDiv);
            statusDiv.innerHTML = "Showing cached data due to error. Auto-updates every 10 minutes.";
            startAutoRefresh();
          } else {
            renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
            statusDiv.innerHTML = "No valid cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
          }
        } catch (err) {
          renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
          statusDiv.innerHTML = "No valid cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
          console.error("Failed to parse cached feed on error:", err);
          localStorage.removeItem("threatFeed"); // Clear corrupted cache
          localStorage.removeItem("threatFeedTime");
        }
      } else {
        renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
        statusDiv.innerHTML = "No cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
      }
      return;
    }

    if (result.type === "feed" && result.ipFeed && result.domainFeed && result.hashFeed && Array.isArray(result.ipFeed) && Array.isArray(result.domainFeed) && Array.isArray(result.hashFeed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      console.log("Cached new feed:", result);
      renderFeed(result, ipFeedDiv, domainFeedDiv, hashFeedDiv);
      statusDiv.innerHTML = "Fetched latest FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds. Auto-updates every 10 minutes.";
      startAutoRefresh();
    } else {
      statusDiv.innerHTML = `No feed data available: ${result.error || "Unexpected response format"}`;
      renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
    }
  } catch (err) {
    statusDiv.innerHTML = `Error: ${err.message}. Using cached data if available.`;
    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        const cachedResult = JSON.parse(cachedFeed);
        if (cachedResult.type === "feed" && cachedResult.ipFeed && cachedResult.domainFeed && cachedResult.hashFeed && Array.isArray(cachedResult.ipFeed) && Array.isArray(cachedResult.domainFeed) && Array.isArray(cachedResult.hashFeed)) {
          renderFeed(cachedResult, ipFeedDiv, domainFeedDiv, hashFeedDiv);
          statusDiv.innerHTML = "Showing cached data due to error. Auto-updates every 10 minutes.";
          startAutoRefresh();
        } else {
          renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
          statusDiv.innerHTML = "No valid cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
        }
      } catch (err) {
        renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
        statusDiv.innerHTML = "No valid cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
        console.error("Failed to parse cached feed on error:", err);
        localStorage.removeItem("threatFeed"); // Clear corrupted cache
        localStorage.removeItem("threatFeedTime");
      }
    } else {
      renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv);
      statusDiv.innerHTML = "No cached data. Failed to fetch FireHOL/Spamhaus/URLhaus/MalwareBazaar feeds.";
    }
    console.error("Feed fetch error:", err);
  }
}

function startAutoRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(() => loadThreatFeed(true), 600000); // Refresh every 10 minutes
}

function renderFeed(result, ipFeedDiv, domainFeedDiv, hashFeedDiv) {
  // IP Feed
  const ipSelect = document.createElement("select");
  ipSelect.className = "feed-select";
  ipSelect.innerHTML = '<option value="">Select an IP</option>';
  result.ipFeed.slice(0, 100).forEach(item => {
    const option = document.createElement("option");
    option.value = item.ipAddress;
    option.textContent = `${item.ipAddress} (${item.source})`;
    ipSelect.appendChild(option);
  });
  ipFeedDiv.innerHTML = "";
  ipFeedDiv.appendChild(ipSelect);

  // Domain Feed
  const domainSelect = document.createElement("select");
  domainSelect.className = "feed-select";
  domainSelect.innerHTML = '<option value="">Select a Domain</option>';
  result.domainFeed.slice(0, 50).forEach(item => {
    const option = document.createElement("option");
    option.value = item.domain;
    option.textContent = `${item.domain} (${item.source})`;
    domainSelect.appendChild(option);
  });
  domainFeedDiv.innerHTML = "";
  domainFeedDiv.appendChild(domainSelect);

  // Hash Feed
  const hashSelect = document.createElement("select");
  hashSelect.className = "feed-select";
  hashSelect.innerHTML = '<option value="">Select a Hash</option>';
  result.hashFeed.slice(0, 50).forEach(item => {
    const option = document.createElement("option");
    option.value = item.hash;
    option.textContent = `${item.hash.slice(0, 16)}... (${item.source})`;
    hashSelect.appendChild(option);
  });
  hashFeedDiv.innerHTML = "";
  hashFeedDiv.appendChild(hashSelect);
}

function renderStaticFeed(ipFeedDiv, domainFeedDiv, hashFeedDiv) {
  // IP Feed
  const ipSelect = document.createElement("select");
  ipSelect.className = "feed-select";
  ipSelect.innerHTML = '<option value="">Select an IP</option>';
  const sampleIPs = [
    { ipAddress: "45.146.164.125", source: "Sample" },
    { ipAddress: "118.25.6.39", source: "Sample" },
    { ipAddress: "185.173.35.14", source: "Sample" },
    { ipAddress: "103.196.36.10", source: "Sample" }
  ];
  sampleIPs.forEach(item => {
    const option = document.createElement("option");
    option.value = item.ipAddress;
    option.textContent = `${item.ipAddress} (${item.source})`;
    ipSelect.appendChild(option);
  });
  ipFeedDiv.innerHTML = "";
  ipFeedDiv.appendChild(ipSelect);

  // Domain Feed
  const domainSelect = document.createElement("select");
  domainSelect.className = "feed-select";
  domainSelect.innerHTML = '<option value="">Select a Domain</option>';
  const sampleDomains = [
    { domain: "example-malicious.com", source: "Sample" },
    { domain: "fake-site.net", source: "Sample" }
  ];
  sampleDomains.forEach(item => {
    const option = document.createElement("option");
    option.value = item.domain;
    option.textContent = `${item.domain} (${item.source})`;
    domainSelect.appendChild(option);
  });
  domainFeedDiv.innerHTML = "";
  domainFeedDiv.appendChild(domainSelect);

  // Hash Feed
  const hashSelect = document.createElement("select");
  hashSelect.className = "feed-select";
  hashSelect.innerHTML = '<option value="">Select a Hash</option>';
  const sampleHashes = [
    { hash: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", source: "Sample" },
    { hash: "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4", source: "Sample" }
  ];
  sampleHashes.forEach(item => {
    const option = document.createElement("option");
    option.value = item.hash;
    option.textContent = `${item.hash.slice(0, 16)}... (${item.source})`;
    hashSelect.appendChild(option);
  });
  hashFeedDiv.innerHTML = "";
  hashFeedDiv.appendChild(hashSelect);
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
