// ================================
// Threat Feed Loader
// ================================
async function loadThreatFeeds(refresh = false) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");
  const feedStatus = document.getElementById("feedStatus");

  feedStatus.innerHTML = "Loading threat feeds...";
  ipFeedDiv.innerHTML = "Loading...";
  domainFeedDiv.innerHTML = "Loading...";
  hashFeedDiv.innerHTML = "Loading...";

  if (!refresh) {
    const cachedFeed = localStorage.getItem("threatFeed");
    const cacheTime = localStorage.getItem("threatFeedTime");
    const cacheAge = cacheTime ? (Date.now() - parseInt(cacheTime)) / (1000 * 60 * 60) : Infinity;

    if (cachedFeed && cacheAge < 24) {
      try {
        const result = JSON.parse(cachedFeed);
        if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
          renderFeeds(result);
          feedStatus.innerHTML = "Loaded from cache (valid 24h). Auto-updates every 10 minutes.";
          startAutoRefresh();
          return;
        }
      } catch (err) {
        console.error("Failed to parse cached feed:", err);
        localStorage.removeItem("threatFeed");
        localStorage.removeItem("threatFeedTime");
      }
    }

    renderStaticFeeds();
    feedStatus.innerHTML = "Showing sample data. Click 'Refresh Feeds' to fetch latest threat intelligence.";
    startAutoRefresh();
    return;
  }

  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();

    if (result.error || (result.errors && result.errors.length > 0)) {
      throw new Error(result.error || `Issues: ${result.errors.join(", ")}`);
    }

    if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      renderFeeds(result);
      feedStatus.innerHTML = "Fetched latest threat intelligence. Auto-updates every 10 minutes.";
      startAutoRefresh();
    } else {
      throw new Error("Invalid feed structure");
    }
  } catch (err) {
    console.error("Feed fetch error:", err);
    feedStatus.innerHTML = `Error fetching threat intelligence: ${err.message}`;
    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        renderFeeds(JSON.parse(cachedFeed));
        feedStatus.innerHTML += " (Showing cached data)";
        startAutoRefresh();
        return;
      } catch (e) {
        console.error("Failed to parse cached feed:", e);
      }
    }
    renderStaticFeeds();
    feedStatus.innerHTML += " (No valid cached data)";
    startAutoRefresh();
  }
}

// ================================
// Static Feeds Fallback
// ================================
function renderStaticFeeds() {
  const today = new Date().toISOString().split("T")[0];
  document.getElementById("ipFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">192.168.1.100</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
      <div class="feed-item"><span class="feed-value">45.33.32.156</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
  document.getElementById("domainFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">phishing-site.com</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
      <div class="feed-item"><span class="feed-value">bad-domain.net</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
  document.getElementById("hashFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">d41d8cd98f00b204...</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
      <div class="feed-item"><span class="feed-value">44d88612fea8a8f3...</span><span class="feed-meta">Sample - Malicious</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
}

// ================================
// Feed Renderer
// ================================
function renderFeeds(result) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  ipFeedDiv.innerHTML = '<div class="feed-list"></div>';
  domainFeedDiv.innerHTML = '<div class="feed-list"></div>';
  hashFeedDiv.innerHTML = '<div class="feed-list"></div>';

  const ipContainer = ipFeedDiv.querySelector(".feed-list");
  const domainContainer = domainFeedDiv.querySelector(".feed-list");
  const hashContainer = hashFeedDiv.querySelector(".feed-list");

  if (!result.feed || !Array.isArray(result.feed)) {
    ipContainer.innerHTML = `<div class="feed-item"><span>No IP data available</span></div>`;
    domainContainer.innerHTML = `<div class="feed-item"><span>No domain data available</span></div>`;
    hashContainer.innerHTML = `<div class="feed-item"><span>No hash data available</span></div>`;
    return;
  }

  result.feed.forEach((item) => {
    const div = document.createElement("div");
    div.className = "feed-item";
    if (item.ipAddress) {
      div.innerHTML = `<span class="feed-value">${item.ipAddress}</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      ipContainer.appendChild(div);
    } else if (item.domain) {
      div.innerHTML = `<span class="feed-value">${item.domain}</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      domainContainer.appendChild(div);
    } else if (item.hash) {
      div.innerHTML = `<span class="feed-value">${item.hash.substring(0, 16)}...</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      hashContainer.appendChild(div);
    }
  });
}

// ================================
// Auto Refresh
// ================================
let autoRefreshTimer = null;
function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(() => loadThreatFeeds(true), 600000);
}
document.getElementById("refresh-feed").addEventListener("click", () => loadThreatFeeds(true));

// ================================
// AbuseIPDB Search Proxy
// ================================
async function searchIndicator() {
  const searchInput = document.getElementById("searchInput");
  const searchResult = document.getElementById("searchResult");
  const indicator = searchInput.value.trim();

  if (!indicator) {
    searchResult.innerHTML = `<p style="color:#888;font-style:italic;">Please enter an IP address.</p>`;
    return;
  }

  searchResult.innerHTML = `<p>Loading...</p>`;

  try {
    // Only IPs supported here
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(indicator)) {
      throw new Error("Only IP searches supported (AbuseIPDB). Use VirusTotal for domains/hashes.");
    }

    const response = await fetch(`/.netlify/functions/abuseipdb-check?ip=${encodeURIComponent(indicator)}`);
    if (!response.ok) throw new Error(`Proxy error: ${response.status}`);
    const data = await response.json();

    if (data.errors && data.errors.length > 0) throw new Error(data.errors[0].detail);

    const d = data.data;
    searchResult.innerHTML = `
      <div class="result-card">
        <div class="info-card">
          <div class="info-grid">
            <span>IP Address:</span><span>${d.ipAddress || 'N/A'}</span>
            <span>Abuse Confidence Score:</span><span>${d.abuseConfidenceScore || 'N/A'}%</span>
            <span>Country Code:</span><span>${d.countryCode || 'N/A'}</span>
            <span>ISP:</span><span>${d.isp || 'N/A'}</span>
            <span>Last Reported:</span><span>${d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleDateString() : 'N/A'}</span>
            <span>Total Reports:</span><span>${d.totalReports || 'N/A'}</span>
          </div>
          <span class="status-badge ${
            d.abuseConfidenceScore >= 75 ? 'status-malicious' :
            d.abuseConfidenceScore >= 50 ? 'status-suspicious' : 'status-clean'
          }">
            ${d.abuseConfidenceScore >= 75 ? 'High Risk' : d.abuseConfidenceScore >= 50 ? 'Suspicious' : 'Clean'}
          </span>
        </div>
      </div>`;
  } catch (err) {
    console.error("Search error:", err);
    searchResult.innerHTML = `<p style="color:#888;">Error: ${err.message}</p>`;
  }
}

// ================================
// Page Init
// ================================
document.addEventListener("DOMContentLoaded", () => loadThreatFeeds(false));
