const  Passport = require("passport");
const { registerUser, login, verifyEmail, resendVerificationEmail, forgotPassword, loginUser, changePassword, changeUserToAdmin } = require("../controllers/userController");
const { authenticate, adminAuth2, adminAuth } = require("../middleware/authentication");
const jwt = require("jsonwebtoken")
const passport = require("passport");

const router = require("express").Router();


router.post("/register", registerUser)

router.get("/user-verify/:token", verifyEmail)

// router.post("/login", login)

router.post("/login", loginUser)

router.post("/make_admin/:userId", adminAuth, changeUserToAdmin)


router.post("/forgot_password", authenticate, adminAuth2, forgotPassword)


router.post("/resend-verification", resendVerificationEmail)

router.post("/change-password", authenticate, changePassword)

router.get("/authenticate", Passport.authenticate("google",{scope: ["profile", "email"]}))
router.get("/auth/google", passport.authenticate("google"), async(req, res) => {
//   console.log(req.user);
const token = await jwt.sign({userId: req.user._id}, process.env.JWT_SECRET, {expiresIn: "1day"})
    res.status(200).json({
        message: "User has been authenticated",
        token,
        user: req.user
})
})


module.exports = router;