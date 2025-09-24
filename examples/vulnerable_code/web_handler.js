// Reflected XSS example
app.get('/greet', (req, res) => {
  res.send("Hello " + req.query.name);
});
