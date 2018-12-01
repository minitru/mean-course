const express = require("express");

const checkAuth = require("../middleware/check-auth.js");

const extractFile = require("../middleware/file.js");

const Post = require("../models/post");

const router = express.Router();

const PostsController = require('../controllers/posts');

router.post(
  "",
  checkAuth,
  extractFile,
   PostsController.createPost);

router.put(
  "/:id",
  checkAuth,
  extractFile,
  PostsController.updatePost);

router.get("", PostsController.getPosts);
router.get("/:id", PostsController.getPost);
router.delete("/:id", checkAuth, PostsController.deletePost);

module.exports = router;
