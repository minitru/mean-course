const express = require('express');
const mongoose = require('mongoose');

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

app.post('/api/posts', (req, res, next) => {
  const post = new Post({
    title: req.body.title,
    content: req.body.content
  });

  post.save().then (createdPost => {
    console.log("ADDED POST: " + createdPost._id + " " + req.body.title + " " + req.body.content);
    res.status(201).json({
      message: 'posts entered ok',
      postId: createdPost._id
    });
  });
});

app.put('/api/posts/:id', (req, res, next) => {
  const post = new Post({
    _id: req.params.id,
    title: req.body.title,
    content: req.body.content
  });
  Post.updateOne({_id: req.body.id}, post).then(result => {
    console.log("UPDATE POST: " + req.params.id + " " + req.body.title + " " + req.body.content);
    res.status(200).json({message: 'Update OK'});
  });
});

app.get('/api/posts',(req, res, next) => {
  Post.find().then(documents => {
    res.status(200).json({
      message: 'posts fetched ok',
      posts: documents
    });
  });
});

app.get('/api/posts/:id', (req, res, next) => {
  Post.findById(req.params.id).then(post => {
    if (post) {
      res.status(200).json(post);
    } else {
      res.status(404).json({ message: 'Post not found' });
    }
  });
});

app.delete('/api/posts/:id',(req, res, next) => {
  Post.deleteOne({ _id: req.params.id }).then(result => {
    console.log(result);
    res.status(200).json({
      message: 'post deleted ok'
    });
  });
});

module.exports = app;
