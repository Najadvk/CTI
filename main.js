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

    console.log("Cache age (hours):", cacheAge, "Cached feed exists:", !!cachedFeed);

    if (cachedFeed && cacheAge < 24) {
      try {
        const result = JSON.parse(cachedFeed);
        console.log("Cached feed:", result);
        if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
          renderFeeds(result);
          feedStatus.innerHTML = "Loaded from cache (valid for 24 hours). Auto-updates every 10 minutes.";
          startAutoRefresh();
          return;
        } else {
          console.warn("Invalid cached feed structure");
          localStorage.removeItem("threatFeed");
          localStorage.removeItem("threatFeedTime");
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
    console.log("Attempting to fetch from /.netlify/functions/fetch-threats");
    const res = await fetch("/.netlify/functions/fetch-threats");
    console.log("Fetch response status:", res.status);
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const result = await res.json();
    console.log("Fetch response:", result);

    if (result.error || (result.errors && result.errors.length > 0)) {
      const errorMsg = result.error || `Fetched feeds with issues: ${result.errors.join(", ")}`;
      feedStatus.innerHTML = `Error: ${errorMsg}. Using cached data if available.`;
      const cachedFeed = localStorage.getItem("threatFeed");
      if (cachedFeed) {
        try {
          const cachedResult = JSON.parse(cachedFeed);
          if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
            renderFeeds(cachedResult);
            feedStatus.innerHTML += " Showing cached data due to error.";
            startAutoRefresh();
            return;
          }
        } catch (err) {
          console.error("Failed to parse cached feed:", err);
        }
      }
      renderStaticFeeds();
      feedStatus.innerHTML = `No valid cached data. ${errorMsg}.`;
      startAutoRefresh();
      return;
    }

    if (result.type === "feed" && result.feed && Array.isArray(result.feed)) {
      localStorage.setItem("threatFeed", JSON.stringify(result));
      localStorage.setItem("threatFeedTime", Date.now().toString());
      renderFeeds(result);
      feedStatus.innerHTML = "Fetched latest threat intelligence (last 24 hours). Auto-updates every 10 minutes.";
      startAutoRefresh();
    } else {
      throw new Error("Invalid feed structure");
    }
  } catch (err) {
    console.error("Feed fetch error:", err);
    feedStatus.innerHTML = `Error: Failed to fetch threat intelligence: ${err.message}. Using cached data if available.`;
    const cachedFeed = localStorage.getItem("threatFeed");
    if (cachedFeed) {
      try {
        const cachedResult = JSON.parse(cachedFeed);
        if (cachedResult.type === "feed" && cachedResult.feed && Array.isArray(cachedResult.feed)) {
          renderFeeds(cachedResult);
          feedStatus.innerHTML += " Showing cached data due to error.";
          startAutoRefresh();
          return;
        }
      } catch (err) {
        console.error("Failed to parse cached feed:", err);
      }
    }
    renderStaticFeeds();
    feedStatus.innerHTML = `No valid cached data. Failed to fetch threat intelligence: ${err.message}.`;
    startAutoRefresh();
  }
}

function renderStaticFeeds() {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  ipFeedDiv.innerHTML = `
    <div class="feed-list">
      <div class="feed-item">
        <span class="feed-value">192.168.1.100</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
      <div class="feed-item">
        <span class="feed-value">45.33.32.156</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
    </div>
  `;
  domainFeedDiv.innerHTML = `
    <div class="feed-list">
      <div class="feed-item">
        <span class="feed-value">phishing-site.com</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
      <div class="feed-item">
        <span class="feed-value">bad-domain.net</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
    </div>
  `;
  hashFeedDiv.innerHTML = `
    <div class="feed-list">
      <div class="feed-item">
        <span class="feed-value">d41d8cd98f00b204e9800998ecf8427e</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
      <div class="feed-item">
        <span class="feed-value">44d88612fea8a8f36de82e1278abb02f</span>
        <span class="feed-meta">Sample - Malicious</span>
        <span class="feed-timestamp">${new Date().toISOString().split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      </div>
    </div>
  `;
}

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
    console.error("Invalid feed data:", result);
    ipContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No IP data available.</span><span class="status-badge status-malicious">Error</span></div>';
    domainContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No domain data available.</span><span class="status-badge status-malicious">Error</span></div>';
    hashContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No hash data available.</span><span class="status-badge status-malicious">Error</span></div>';
    return;
  }

  result.feed.forEach((item, index) => {
    if (!item) {
      console.warn(`Skipping null feed item at index ${index}`);
      return;
    }
    const div = document.createElement("div");
    div.className = "feed-item";
    if (item.ipAddress) {
      div.innerHTML = `
        <span class="feed-value">${item.ipAddress}</span>
        <span class="feed-meta">${item.category} - ${item.source}</span>
        <span class="feed-timestamp">${item.first_seen.split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      `;
      ipContainer.appendChild(div);
    } else if (item.domain) {
      div.innerHTML = `
        <span class="feed-value">${item.domain}</span>
        <span class="feed-meta">${item.category} - ${item.source}</span>
        <span class="feed-timestamp">${item.first_seen.split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      `;
      domainContainer.appendChild(div);
    } else if (item.hash) {
      div.innerHTML = `
        <span class="feed-value">${item.hash.substring(0, 16)}...</span>
        <span class="feed-meta">${item.category} - ${item.source}</span>
        <span class="feed-timestamp">${item.first_seen.split("T")[0]}</span>
        <span class="status-badge status-malicious">Malicious</span>
      `;
      hashContainer.appendChild(div);
    } else {
      console.warn(`Invalid feed item at index ${index}:`, item);
    }
  });

  console.log("Rendered feed:", {
    ipCount: ipContainer.children.length,
    domainCount: domainContainer.children.length,
    hashCount: hashContainer.children.length,
  });

  if (ipContainer.children.length === 0) {
    ipContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No IP data available.</span><span class="status-badge status-malicious">Error</span></div>';
  }
  if (domainContainer.children.length === 0) {
    domainContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No domain data available.</span><span class="status-badge status-malicious">Error</span></div>';
  }
  if (hashContainer.children.length === 0) {
    hashContainer.innerHTML = '<div class="feed-item"><span class="feed-value">No hash data available.</span><span class="status-badge status-malicious">Error</span></div>';
  }
}

let autoRefreshTimer = null;

function startAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
  }
  autoRefreshTimer = setInterval(() => {
    console.log("Auto refreshing threat feeds...");
    loadThreatFeeds(true);
  }, 600000);
}

// Refresh button handler
document.getElementById("refresh-feed").addEventListener("click", () => {
  loadThreatFeeds(true);
});

// Initial load on page ready
document.addEventListener("DOMContentLoaded", () => {
  loadThreatFeeds(false);
});
