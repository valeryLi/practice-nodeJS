const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  try {
    // read the token from Headers
    const [tokenType, token] = req.headers.authorization.split(" ");

    // check, that token will be passed and it's authorization token
    // if all good, decipher(decode) token
    if (token && tokenType === "Bearer") {
      const decodedData = jwt.verify(token, "pizza");

      req.user = decodedData;

      next();
    }

    // if something wrong, says that user is not authorized
  } catch (error) {
    res.status(401).json({
      code: 401,
      message: "Not authorized",
      error: error.message,
    });
  }
};
