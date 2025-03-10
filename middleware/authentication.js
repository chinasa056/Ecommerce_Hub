const userModel = require("../models/user");
const jwt = require("jsonwebtoken");

// exports.authenticate = async (req, res, next) => {
//     try {
//         // get the token from the authorization header
//         const auth = req.headers.authorization;
//         if (!auth) {
//             return res.status(404).json({
//                 message: " TOken not found",
//             })
//         };

//         // make sure the token is valid
//         const token = auth.split(" ")[1];
//         if (!token) {
//             return res.status(400).json({
//                 message: "Invalid Token",
//             })
//         };

//         // verify the token to be sure its still valid
//         const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
//         // check if the user is still existing
//         const user = await userModel.findById(decodedToken.userId);
//         if (!user) {
//             return res.status(404).json({
//                 message: " Authentication Failed: user not found",
//             })
//         };

//         // pass the payload to the request user object
//         req.user = decodedToken;
//         // call the next function
//         next()

//     } catch (error) {
//         console.log(error.message);
//         if (error instanceof jwt.JsonWebTokenError) {
//             return res.status(400).json({
//                 message: " Session timed-out, Please login to continue",
//             })
//         }
//          res.status(500).json({
//             message: " Internal server error",
//         })
//     }
// };

// exports.authenticateAdmin = async (req, res, next) => {
//     try {
//         // /get the token from the authorization head
//         const auth = req.headers.authorization
//         // make sure the token is  a valid JWT token
//         const token = auth.split(" ") [1];
//         if(!token) {
//             return res.status(400).json({
//                 message: " Invalid Token",
//             })
//         };

//         // verify the token to besue it is still vaild
//         const decodedToken = await jwt.verify(token, process.env.JWT_SECRET);
//         // check if the user is still existing
//         const user = await userModel.findById(decodedToken.userId);
//         if(!user) {
//             return res.status(400).json({
//                 message: " Authentication Failed: User not found",
//             })
//         };
//         if(user.isVerified === false) {
//             return res.status(401).json({
//                 message: " Unauthorized: You are not allowed to perform this action",
//             })
//         };
//         // pass the payload to the request user object
//         req.user = decodedToken;
//         // call the next action
//         next();

//     } catch (error) {
//         console.log(error.message);
//         if (error instanceof jwt.JsonWebTokenError) {
//             return res.status(400).json({
//                 message: " Session timed-out, Please login to continue",
//             })
//         }
//          res.status(500).json({
//             message: " Internal server error",
//         })
//     }
// }

exports.authenticate = async (req, res, next) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) {
      return res.status(400).json({
        message: "Token not found",
      });
    }
    const token = auth.split(" ")[1];
    if (!token) {
      return res.status(400).json({
        message: "Invalid token",
      });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decodedToken.userId);
    if (!user) {
      return res.status(404).json({
        message: "Authentication Failed: User not found",
      });
    }
    req.user = decodedToken;

    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(403).json({
        message: "Session timed-out: Please login to continue",
      });
    }
    res.status(500).json({
      message: "Internal Server Error" + error.message,
    });
  }
};

exports.adminAuth = async (req, res, next) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) {
      return res.status(400).json({
        message: "Token not found",
      });
    }

    const token = auth.split(" ")[1];
    if (!token) {
      return res.status(400).json({
        message: "Invalid token",
      });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decodedToken.userId);
    if (!user) {
      return res.status(404).json({
        message: "Authentication Failed: User not found",
      });
    }

    if (user.isAdmin !== true) {
      return res.status(401).json({
        message: "Unauthorized: Please contact Admin",
      });
    }

    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(500).json({
      message: "Internal Server Error" + error.message,
    });
  }
};

exports.adminAuth2 = async (req, res, next) => {
  try {
    if (req.user.isAdmin !== true) {
      return res.status(401).json({
        message: "Unauthorized: Not an Admin",
      });
    }
    next();
  } catch (error) {
    res.status(500).json({
      message: "Internal Server Error" + error.message,
    });
  }
};
