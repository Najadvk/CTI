const fs = require('fs');
const path = require('path');

exports.handler = async (event) => {
  const domain = event.queryStringParameters.domain;
  const filePath = path.join(__dirname, '..', '..', 'feed.json');
  const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

  const status = data.domains[domain] || 'unknown';
  return {
    statusCode: 200,
    body: JSON.stringify({ domain, status }),
  };
};
