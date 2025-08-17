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

function renderFeeds(result) {
  const ipFeedDiv = document.getElementById("ipFeed");
  const domainFeedDiv = document.getElementById("domainFeed");
  const hashFeedDiv = document.getElementById("hashFeed");

  ipFeedDiv.innerHTML = "<ul></ul>";
  domainFeedDiv.innerHTML = "<ul></ul>";
  hashFeedDiv.innerHTML = "<ul></ul>";

  const ipList = ipFeedDiv.querySelector("ul");
  const domainList = domainFeedDiv.querySelector("ul");
  const hashList = hashFeedDiv.querySelector("ul");

  if (!result.feed || !Array.isArray(result.feed)) {
    console.error("Invalid feed data:", result);
    ipList.innerHTML = "<li>No IP data available.</li>";
    domainList.innerHTML = "<li>No domain data available.</li>";
    hashList.innerHTML = "<li>No hash data available.</li>";
    return;
  }

  result.feed.forEach((item, index) => {
    if (!item) {
      console.warn(`Skipping null feed item at index ${index}`);
      return;
    }
    const li = document.createElement("li");
    if (item.ipAddress) {
      li.textContent = `${item.ipAddress} (${item.category} - ${item.source})`;
      ipList.appendChild(li);
    } else if (item.domain) {
      li.textContent = `${item.domain} (${item.category} - ${item.source})`;
      domainList.appendChild(li);
    } else if (item.hash) {
      li.textContent = `${item.hash} (${item.category} - ${item.source})`;
      hashList.appendChild(li);
    } else {
      console.warn(`Invalid feed item at index ${index}:`, item);
    }
  });

  console.log("Rendered feed:", {
    ipCount: ipList.children.length,
    domainCount: domainList.children.length,
    hashCount: hashList.children.length,
  });

  if (ipList.children.length === 0) {
    ipList.innerHTML = "<li>No IP data available.</li>";
  }
  if (domainList.children.length === 0) {
    domainList.innerHTML = "<li>No domain data available.</li>";
  }
  if (hashList.children.length === 0) {
    hashList.innerHTML = "<li>No hash data available.</li>";
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
