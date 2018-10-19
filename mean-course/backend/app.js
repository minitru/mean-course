const express = require('express');

const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  next();
});

app.post('/api/posts',(req, res, next) => {
  const post = req.body;
  console.log(post);
  res.status(201).json({
    message: 'posts entered ok'
  });
});

app.get('/api/posts',(req, res, next) => {
  const posts = [
    { id: 'a123', title: 'First title', content: 'first content'},
    { id: 'a222', title: 'Second title', content: 'Second content'},
  ];
  res.status(200).json({
    message: 'posts fetched ok',
    posts: posts
  });
});

module.exports = app;
