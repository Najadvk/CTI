document.getElementById('search-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ioc = document.getElementById('ioc').value.trim();
  let url;

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) {
    url = `/.netlify/functions/lookup-ip?ip=${ioc}`;
  } else if (ioc.includes('.')) {
    url = `/.netlify/functions/lookup-domain?domain=${ioc}`;
  } else {
    url = `/.netlify/functions/lookup-hash?hash=${ioc}`;
  }

  const res = await fetch(url);
  const data = await res.json();
  const status = Object.values(data)[1]; // grabs the "status" value
  document.getElementById('detected-type').textContent = status;
});
