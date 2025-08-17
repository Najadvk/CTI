/* ===== Utility: Toast Notifications ===== */
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  document.body.appendChild(toast);

  setTimeout(() => toast.classList.add("show"), 100); // Animate in
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

/* ===== Utility: Loading Skeleton ===== */
function createSkeletonFeed(count = 3) {
  let skeletons = "";
  for (let i = 0; i < count; i++) {
    skeletons += `
      <div class="feed-item skeleton">
        <span class="feed-value"></span>
        <span class="feed-meta"></span>
        <span class="feed-timestamp"></span>
        <span class="status-badge"></span>
      </div>`;
  }
  return `<div class="feed-list">${skeletons}</div>`;
}

/* ===== Threat Feeds Loader ===== */
async function loadThreatFeeds(refresh = false) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");
  const feedStatus = document.getElementById("feedStatus");

  // Show skeleton loaders
  feedStatus.innerHTML = `<span class="loading-spinner"></span> Fetching threat feeds...`;
  ipFeedDiv.innerHTML = createSkeletonFeed();
  domainFeedDiv.innerHTML = createSkeletonFeed();
  hashFeedDiv.innerHTML = createSkeletonFeed();

  if (!refresh) {
    const cachedFeed = localStorage.getItem("threatFeed");
    const cacheTime = localStorage.getItem("threatFeedTime");
    const cacheAge = cacheTime ? (Date.now() - parseInt(cacheTime)) / (1000 * 60 * 60) : Infinity;

    if (cachedFeed && cacheAge < 24) {
      try {
        const result = JSON.parse(cachedFeed);
        if (result.type === "feed" && Array.isArray(result.feed)) {
          renderFeeds(result);
          feedStatus.innerHTML = `✅ Loaded from cache (valid 24h) — Auto-updates every 10 min`;
          startAutoRefresh();
          return;
        }
      } catch {
        localStorage.removeItem("threatFeed");
        localStorage.removeItem("threatFeedTime");
      }
    }
    renderStaticFeeds();
    feedStatus.innerHTML = `📄 Showing sample data. Click <b>Refresh Feeds</b> for live intelligence.`;
    startAutoRefresh();
    return;
  }

  try {
    const res = await fetch("/.netlify/functions/fetch-threats");
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();

    if (result.type === "feed" && Array.isArray(result.feed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      renderFeeds(result);
      feedStatus.innerHTML = `✅ Live threat intelligence (last 24h). Auto-refresh every 10 min.`;
      showToast("Feeds updated successfully", "success");
      startAutoRefresh();
    } else {
      throw new Error("Invalid feed structure");
    }
  } catch (err) {
    console.error("Feed fetch error:", err);
    feedStatus.innerHTML = `⚠️ Failed to fetch live data — showing cached or sample feeds.`;
    showToast("Failed to update feeds", "error");

    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        renderFeeds(JSON.parse(cachedFeed));
        feedStatus.innerHTML += ` ✅ Using cached feeds.`;
        return;
      } catch {}
    }
    renderStaticFeeds();
  }
}

/* ===== Static Sample Feeds (fallback) ===== */
function renderStaticFeeds() {
  const today = new Date().toISOString().split("T")[0];
  document.getElementById("ipFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">192.168.1.100</span><span class="feed-meta">Sample</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
      <div class="feed-item"><span class="feed-value">45.33.32.156</span><span class="feed-meta">Sample</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
  document.getElementById("domainFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">phishing-site.com</span><span class="feed-meta">Sample</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
  document.getElementById("hashFeed").innerHTML = `
    <div class="feed-list">
      <div class="feed-item"><span class="feed-value">d41d8cd98f00b2...</span><span class="feed-meta">Sample</span><span class="feed-timestamp">${today}</span><span class="status-badge status-malicious">Malicious</span></div>
    </div>`;
}

/* ===== Feed Renderer ===== */
function renderFeeds(result) {
  const ipFeedDiv = document.getElementById("ipFeed").querySelector(".feed-list") || document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed").querySelector(".feed-list") || document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed").querySelector(".feed-list") || document.getElementById("hashFeed");

  ipFeedDiv.innerHTML = "";
  domainFeedDiv.innerHTML = "";
  hashFeedDiv.innerHTML = "";

  result.feed.forEach(item => {
    if (!item) return;
    const div = document.createElement("div");
    div.className = "feed-item fade-in";

    if (item.ipAddress) {
      div.innerHTML = `<span class="feed-value">${item.ipAddress}</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      ipFeedDiv.appendChild(div);
    } else if (item.domain) {
      div.innerHTML = `<span class="feed-value">${item.domain}</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      domainFeedDiv.appendChild(div);
    } else if (item.hash) {
      div.innerHTML = `<span class="feed-value">${item.hash.substring(0, 16)}...</span><span class="feed-meta">${item.category} - ${item.source}</span><span class="feed-timestamp">${item.first_seen.split("T")[0]}</span><span class="status-badge status-malicious">Malicious</span>`;
      hashFeedDiv.appendChild(div);
    }
  });
}

/* ===== Auto Refresh ===== */
let autoRefreshTimer = null;
function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(() => loadThreatFeeds(true), 600000); // 10 min
}

/* ===== Refresh Button ===== */
document.getElementById("refresh-feed").addEventListener("click", () => {
  showToast("Refreshing feeds...", "info");
  loadThreatFeeds(true);
});

/* ===== Search Indicator ===== */
async function searchIndicator() {
  const input = document.getElementById("searchInput").value.trim();
  const resultDiv = document.getElementById("searchResult");

  if (!input) {
    resultDiv.innerHTML = `<p class="muted">⚠️ Please enter an IP.</p>`;
    return;
  }

  resultDiv.innerHTML = `<div class="loading-spinner"></div> Checking...`;

  try {
    const keyRes = await fetch("/api/get-api-key");
    const { apiKey } = await keyRes.json();
    if (!apiKey) throw new Error("API key missing");

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(input)) throw new Error("Only IPs supported (e.g., 8.8.8.8)");

    const response = await fetch(`https://api.abuseipdb.com/api/v2/check`, {
      method: "POST",
      headers: { "Key": apiKey, "Accept": "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ ipAddress: input, maxAgeInDays: 90 })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    resultDiv.innerHTML = `
      <div class="result-card fade-in">
        <div class="info-grid">
          <span>IP Address:</span><span>${data.data.ipAddress || "N/A"}</span>
          <span>Confidence:</span><span>${data.data.abuseConfidenceScore || "N/A"}%</span>
          <span>Country:</span><span>${data.data.countryCode || "N/A"}</span>
          <span>ISP:</span><span>${data.data.isp || "N/A"}</span>
          <span>Last Reported:</span><span>${data.data.lastReportedAt ? new Date(data.data.lastReportedAt).toLocaleDateString() : "N/A"}</span>
          <span>Total Reports:</span><span>${data.data.totalReports || "N/A"}</span>
        </div>
        <span class="status-badge ${data.data.abuseConfidenceScore >= 75 ? "status-malicious" : data.data.abuseConfidenceScore >= 50 ? "status-suspicious" : "status-clean"}">
          ${data.data.abuseConfidenceScore >= 75 ? "High Risk" : data.data.abuseConfidenceScore >= 50 ? "Suspicious" : "Clean"}
        </span>
      </div>`;
  } catch (err) {
    resultDiv.innerHTML = `<p class="muted">❌ Error: ${err.message}</p>`;
  }
}

/* ===== On Page Load ===== */
document.addEventListener("DOMContentLoaded", () => loadThreatFeeds(false));
