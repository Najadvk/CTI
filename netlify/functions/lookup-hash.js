const fs = require('fs');
const path = require('path');

exports.handler = async (event) => {
  const hash = event.queryStringParameters.hash;
  const filePath = path.join(__dirname, '..', '..', 'feed.json');
  const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

  const status = data.hashes[hash] || 'unknown';
  return {
    statusCode: 200,
    body: JSON.stringify({ hash, status }),
  };
};
