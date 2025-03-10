const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require("passport")
const userModel = require("../models/user")

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENTID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://ecommerce-hub-ykfb.onrender.com/api/v1/auth/google"
  },
  async(accessToken, refreshToken, profile, cb) =>  {
    // console.log(profile)
   try {
    const checkUser = await userModel.findOne({ email: profile.emails[0].value })

   if (!checkUser) {
    const newUser = new userModel({
      fullName: profile.displayName,
      email: profile.emails[0].value,
      isVerified: profile.emails[0].verified,
    })
    await newUser.save()
  }
  return cb(null, checkUser)
   } catch (error) {
    return cb(error, null)
   }
  }

));

passport.serializeUser((user, cb)=> {
  cb(null, user.id)
});

passport.deserializeUser( async(id, cb) => {
  await userModel.findById(id)
  cb(null, user)
})