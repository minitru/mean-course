const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  try {
    // console.log(req.headers.authorization);
    // CAREFUL HERE - SPLIT RETURNS AN ARRAY AND [1] POINTS TO THE SECOND ELEMENT
    // AFTER Bearer aspodapsdasdasd
    // BUG WAS req.headers.authorization.split(" ", [1]);
    const token = req.headers.authorization.split(" ")[1];
    // ENV VARIABLE LIVES IN nodemon.json env ARRAY
    const decodedToken = jwt.verify(token, process.env.JWT_KEY);
    req.userData = { email: decodedToken.email, userId: decodedToken.userId };
    next();
  } catch (error) {
    res.status(401).json({ message: 'Middleware check-auth Auth failed!' });
  }
};
