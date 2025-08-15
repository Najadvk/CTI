const fs = require('fs');
const path = require('path');

exports.handler = async (event) => {
  const ip = event.queryStringParameters.ip;
  const filePath = path.join(__dirname, '..', '..', 'feed.json');
  const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

  const status = data.ips[ip] || 'unknown';
  return {
    statusCode: 200,
    body: JSON.stringify({ ip, status }),
  };
};
