import express from 'express';

const app = express();
const port = 8081;

app.get('/process', (req, res) => {
  const { code, state, error, error_description } = req.query;
  
  if (error) {
    res.status(400).json({
      status: "error",
      error: error,
      error_description: error_description
    });
  } else {
    res.json({
      status: "success",
      code: code,
      state: state || null
    });
  }
});


app.listen(port, () => {
  console.log(`Client server running on http://localhost:${port}`);
});
