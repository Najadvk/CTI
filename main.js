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


// Refresh button handler
document.getElementById("refresh-feed").addEventListener("click", () => {
  loadThreatFeeds(true);
});

// Initial load on page ready
document.addEventListener("DOMContentLoaded", () => {
  loadThreatFeeds(false);
});


// Fallback static sample feeds (in case API/cached feed fails)
function renderStaticFeeds() {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  ipFeedDiv.innerHTML = `
    <ul>
      <li>192.168.1.100 (Sample - Malicious)</li>
      <li>45.33.32.156 (Sample - Malicious)</li>
    </ul>
  `;

  domainFeedDiv.innerHTML = `
    <ul>
      <li>phishing-site.com (Sample - Malicious)</li>
      <li>bad-domain.net (Sample - Malicious)</li>
    </ul>
  `;

  hashFeedDiv.innerHTML = `
    <ul>
      <li>d41d8cd98f00b204e9800998ecf8427e (Sample - Malicious)</li>
      <li>44d88612fea8a8f36de82e1278abb02f (Sample - Malicious)</li>
    </ul>
  `;
}
// Auto-refresh feed every 10 minutes
let autoRefreshTimer = null;

function startAutoRefresh() {
  // Clear any existing timer so we don't stack multiple
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
  }

  // Refresh every 10 minutes (600,000 ms)
  autoRefreshTimer = setInterval(() => {
    console.log("Auto refreshing threat feeds...");
    loadThreatFeeds(true); // force refresh
  }, 600000);
}


// Assume renderFeeds, renderStaticFeeds, startAutoRefresh are defined elsewhere in main.js
