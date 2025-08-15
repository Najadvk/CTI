const tableBody = document.querySelector('#threat-table tbody');
const searchInput = document.querySelector('#ioc');
const searchForm = document.querySelector('#search-form');

let threatData = {};

// Fetch threat feed from Netlify function
async function fetchThreatFeed() {
  try {
    const response = await fetch('/.netlify/functions/fetch-threats');
    threatData = await response.json();
    displayTable(threatData);
  } catch (error) {
    console.error('Failed to fetch threat feed:', error);
    tableBody.innerHTML = '<tr><td colspan="3">Failed to load threat feed</td></tr>';
  }
}

// Display table rows
function displayTable(data) {
  tableBody.innerHTML = '';
  for (const [ip, status] of Object.entries(data.ips || {})) {
    addRow('IP', ip, status);
  }
  for (const [domain, status] of Object.entries(data.domains || {})) {
    addRow('Domain', domain, status);
  }
  for (const [hash, status] of Object.entries(data.hashes || {})) {
    addRow('Hash', hash, status);
  }
}

// Add a single row
function addRow(type, indicator, status) {
  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${type}</td>
    <td>${indicator}</td>
    <td class="status-${status}">${status}</td>
  `;
  tableBody.appendChild(row);
}

// Search functionality
searchForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const query = searchInput.value.trim().toLowerCase();
  if (!query) return;
  
  const filteredData = { ips: {}, domains: {}, hashes: {} };
  
  for (const [ip, status] of Object.entries(threatData.ips || {})) {
    if (ip.includes(query)) filteredData.ips[ip] = status;
  }
  for (const [domain, status] of Object.entries(threatData.domains || {})) {
    if (domain.includes(query)) filteredData.domains[domain] = status;
  }
  for (const [hash, status] of Object.entries(threatData.hashes || {})) {
    if (hash.includes(query)) filteredData.hashes[hash] = status;
  }

  displayTable(filteredData);
});

// Initial fetch
fetchThreatFeed();

// Refresh every 24 hours
setInterval(fetchThreatFeed, 24 * 60 * 60 * 1000);
