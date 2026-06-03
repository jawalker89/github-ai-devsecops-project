const express = require('express');
const axios = require('axios');
const _ = require('lodash');

const app = express();
const PORT = 3000;

app.get('/', async (req, res) => {
  const greeting = _.join(['Hello', 'World'], ' ');

  try {
    const response = await axios.get(
      'https://jsonplaceholder.typicode.com/todos/1'
    );

    res.send(`
      <h1>${greeting}</h1>
      <p>AI DevSecOps vulnerable demo app</p>
      <pre>${JSON.stringify(response.data, null, 2)}</pre>
    `);
  } catch (err) {
    res.send(`<h1>${greeting}</h1><p>Error fetching data</p>`);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
