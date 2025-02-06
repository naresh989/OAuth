import express from 'express';

const app = express();
const port = 8081;

app.get('/process', (req, res) => {
  const { code, state, error, error_description } = req.query;
  if (error) {
    res.status(400).send(`Error: ${error}<br>Description: ${error_description}`);
  } else {
    res.send(`<h1>Authorization Successful</h1>
      <p>Code: ${code}</p>
      ${state ? `<p>State: ${state}</p>` : ''}`);
  }
});

app.listen(port, () => {
  console.log(`Client server running on http://localhost:${port}`);
});