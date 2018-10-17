const express = require('express');

const app = express();



app.use('/api/posts',(req, res, next) => {
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
