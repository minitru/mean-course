const Post = require("../models/post");

exports.createPost = (req, res, next) => {
  const url = req.protocol + "://" + req.get("host");
  const post = new Post({
    title: req.body.title,
    content: req.body.content,
    imagePath: url + "/images/" + req.file.filename,
    creator: req.userData.userId
  });
  post.save().then(createdPost => {
    res.status(201).json({
      message: "Post added successfully",
      post: {
        ...createdPost,
        id: createdPost._id
      }
    });
  })
 .catch(err => {
   res.status(500).json({
    message: 'Post failed'
   })
  });
}

exports.updatePost = (req, res, next) => {
  let imagePath = req.body.imagePath;
  if (req.file) {
    const url = req.protocol + "://" + req.get("host");
    imagePath = url + "/images/" + req.file.filename
  }
  const post = new Post({
    _id: req.body.id,
    title: req.body.title,
    content: req.body.content,
    imagePath: imagePath,
    creator: req.userData.userId
  });
  console.log(post);
  Post.updateOne({ _id: req.params.id, creator: req.userData.userId }, post).then(result => {
    // IF THE NUMBER OF ELEMENTS IN THE DB THAT WERE MODIFIED
    if (result.nModified > 0) {
      res.status(200).json({ message: "Update successful!" });
    } else {
      res.status(401).json({ message: "Update Permission Denied!" });
    }
  })
  .catch(error => {
    res.status(500).json({
      message: 'Server error - couldn\'t update post'
    });
  });
}

exports.getPosts = (req, res, next) => {
  const pageSize = +req.query.pagesize;   // + CONVERTS STR->NUM
  const currentPage = +req.query.page;
  const postQuery = Post.find();
  let fetchedPosts;
  if (pageSize && currentPage) {
    postQuery
    .skip(pageSize * (currentPage - 1))
    .limit(pageSize);
  }
  postQuery.then(documents => {
    fetchedPosts = documents;
    return Post.count();
  }).then( count => {
    res.status(200).json({
      message: "Posts fetched successfully!",
      posts: fetchedPosts,
      maxPosts: count
    })
    .catch(err => {
      res(500).json({message: 'Server error - can\t fetch posts'})
    })
  })
}

exports.getPost = (req, res, next) => {
  Post.findById(req.params.id).then(post => {
    if (post) {
      res.status(200).json(post);
    } else {
      res.status(404).json({ message: "Post not found!" });
    }
  })
  .catch(err => {
    res(500).json({message: 'Server error - can\t find posts'})
  })
}

exports.deletePost = (req, res, next) => {
  Post.deleteOne({ _id: req.params.id, creator: req.userData.userId }).then(result => {
    // IF THE NUMBER OF ELEMENTS IN THE DB THAT WERE AFFECTED
    if (result.n > 0) {
     res.status(200).json({ message: "Update successful!" });
    } else {
     res.status(401).json({ message: "Update Permission Denied!" });
    }
  })
  .catch(err => {
    res(500).json({message: 'Server error - can\t delete posts'})
  })
}
