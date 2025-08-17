import { handler } from './netlify/functions/fetch-threats.js';

// Test the handler function
const testEvent = {
  queryStringParameters: null
};

const testContext = {};

handler(testEvent, testContext)
  .then(result => {
    console.log('Status Code:', result.statusCode);
    const body = JSON.parse(result.body);
    console.log('Response Type:', body.type);
    console.log('Feed Items:', body.feed ? body.feed.length : 0);
    if (body.feed && body.feed.length > 0) {
      console.log('Sample items:');
      body.feed.slice(0, 5).forEach((item, index) => {
        console.log(`${index + 1}:`, item);
      });
    }
    if (body.error) {
      console.log('Error:', body.error);
    }
  })
  .catch(error => {
    console.error('Test failed:', error);
  });

