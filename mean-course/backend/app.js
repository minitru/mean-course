const express = require('express');
const mongoose = require('mongoose');

const postsRoutes = require('./routes/posts');

const app = express();

mongoose.connect("mongodb://dev.maclawran.ca/node-angular?retryWrites=true")
  .then(() => {
    console.log('Connected to mongo OK');
  })
  .catch(() => {
    console.log('Mongo error!');
  });

const bodyParser = require('body-parser');

const Post = require('./models/post');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,PATCH,DELETE,OPTIONS');
  next();
});

app.use('/api/posts', postsRoutes);

module.exports = app;
