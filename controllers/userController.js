const userModel = require("../models/user");
const bcrypt = require("bcrypt");
const sendMail = require("../middleware/nodemailer")
const jwt = require("jsonwebtoken");
const { signUpTemplate, forgotPasswordTemplate } = require("../utils/mailTemplate");
const { validate } = require("../utils/utilities");
const { reqisterUserSchema, loginSchema } = require("../validation/userValidation");
// const {sign}

// ONBOARDING STAGE

exports.registerUser = async (req, res) => {
    try {
        const validatedData = await validate(req.body, reqisterUserSchema)
        // extract the rquired fields from the request body
        const { fullName, email, password, gender, userName } = validatedData
        // check if the user is existing
        const user = await userModel.findOne({ email: email.toLowerCase() })

        if (user) {
            return res.status(400).json({
                message: `User with email ${email} already exists`
            })
        };

        const randomNumber = Math.floor(Math.random() * 100);

        // check if the userNme is existing
        const userNameExists = await userModel.findOne({ userName: userName.toLowerCase() })
        if (userNameExists) {
            return res.status(400).json({
                message: `UserName already exists, try ${userName} + ${randomNumber}`
            })
        };

        // encrypt the users password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)

        // create an instance of the document
        const newUser = new userModel({
            fullName,
            email,
            password: hashedPassword,
            gender,
            userName

        })

        // generate a token for the user
        const token = await jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // configure the link to verify the user
        const link = `${req.protocol}://${req.get("host")}/api/v1/user-verify/${token}`
        const firstName = newUser.fullName.split(" ")[1]
        const html = signUpTemplate(link, firstName)

        // send the user a mail
        const mailOptions = {
            subject: "Welcoming Email",
            email: newUser.email,
            html
        }
        // await the nodemaileer to send the email to the user
        await sendMail(mailOptions);

        // save the doecumant to the database
        await newUser.save()

        res.status(201).json({
            message: "User registered successfully",
            data: newUser
        })

    } catch(error) {
        // console.error(error);
        res.status(500).json({
            message: "Error registering User",
            error: error.message
        })
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        // extract the token from the params
        const { token } = req.params;
        // check if the token is not available
        if (!token) {
            return res.status(400).json({
                message: "Token not found"
            })
        };

        // verify the token
        const decodedToken = await jwt.verify(token, process.env.JWT_SECRET)
        // find the user by the decoded token id
        const user = await userModel.findById(decodedToken.userId);
        // throw an error if the user is not found
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        };
        // update the isVerified field to be true
        user.isVerified = true;

        // save the changes to the database
        await user.save()

        // send a success response
        res.status(200).json({
            message: "User verified successfully"
        })

    } catch (error) {
        console.error(error);
        if (error instanceof jwt.JsonWebTokenError) {
            res.status(500).json({
                message: "Verification link expired"
            })
        }
        res.status(500).json({
            message: "Error verifying user User"
        })
    }
};

exports.resendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;
        // check if the token is not available
        if (!email) {
            return res.status(400).json({
                message: "Please enter email address"
            })
        };
        const user = await userModel.findOne({ email: email.toLowerCase() });
        // throw an error if user is not found
        if (!user) {
            return res.status(400).json({
                message: "User not found"
            })
        };

        // Generate a token for the user
        const token = await jwt.sign({ userId: user._id }, pocess.env.JWT_SECRET, { expiresIn: "1hour" });
        // configure the link to verify the user
        const link = `${req.protocol}://${req.get("host")}/api/v1/user-verify/${token}`
        const firstName = user.fullName.split(" ")[1]
        const html = signUpTemplate(link, firstName);

        // send the user an email
        const mailOptions = {
            subject: "Email verification",
            email: user.email,
            html
        };

        // await the nodemailer to send the email to the user
        await sendMail(mailOptions);
        // send a success response
        res.status(400).json({
            message: "Verification email successful, please check your email"
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: "Error resending verification email" + error.message
        })
    }
};

// FORGOT PASSWORD
exports.forgotPassword = async (req, res) => {
    try {
        // get the email from the request boddy
        const { email } = req.body;

        if (email == null) {
            return res.status(400).json({
                message: "Please enter your email"
            })
        };

        const user = await userModel.findOne({ email: email.toLowerCase() })
        if (!user) {
            return res.status(404).json({
                message: "user not found"
            })
        };

        // generate a token for the user
        const token = await jwt.sign({ userid: user._id }, process.env.JWT_SECRET, { expiresIn: "10mins" })

        const link = `${req.protocol}: //${req.get("host")}/api/v1/forgot_password/${token}`
        const firstName = user.fullName.split(" ")[0]

        // pass the email details to a variable
        const mailDetails = {
            subject: "password reset",
            email: user.email,
            html: forgotPasswordTemplate(link, firstName)
        }

        // await nodemailer to send the email
        await sendMail(mailDetails)

        // send a sucess response
        res.status(200).json({
            message: "Reset password initiated, please check your eamil for the reset link "
        })

    } catch (error) {
        console.error(error);
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(500).json({
                message: "Link Expired"
            })
        }
        res.status(500).json({
            message: "Internal server error"
        })
    }
};

exports.resetPassword = async (req, res) => {
    try {
        // extract the token from the params
        const { token } = req.params
        // extract the password and confirm password from the req.body
        const { password, confirmPassword } = req.body;
        // verify the token id dtill valid, extract the userID from the tokn and use it to find the usr in the database
        const { userId } = await jwt.verify(token, process.env.JWT_SECRET);
        // find the user in the database
        const user = await userModel.findById(userId)

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        };

        // confirm the password matches the confirm password
        if (password !== confirmPassword) {
            return res.status(400).json({
                message: "Password does not match"
            })
        };

        // generate a salt and hash password for the user
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user.password = hashedPassword

        // save the changes to the database
        await user.save()

        // senda sucess response
        res.status(200).json({
            message: "Password reset successful"
        })


    } catch (error) {
        console.error(error);
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(500).json({
                message: "Link Expired"
            })
        }
        res.status(500).json({
            message: "Internal server error"
        })
    }
}

// exports.login = async (req, res) => {
//     try {
//         // extract the email and pasword from the req.body
//         const { email, password } = req.body;
//         const userExists = await userModel.findOne({ email: email.toLowerCase() });

//         // check if the user is existing
//         if (userExists === null) {
//             return res.status(404).json({
//                 message: `User with email ${email} does not found`
//             })
//         };

//         // confirm the users password
//         const isCorrectPassword = await bcrypt.compare(password, userExists.password);
//         if (isCorrectPassword === false) {
//             return res.status(400).json({
//                 message: "Incorrect password"
//             })
//         };

//         // check if theuser is verified
//         if (userExists.isVerified === false) {
//             return res.status(400).json({
//                 message: "User not verified, please check your email to verify"
//             })
//         };

//         // generate a token for the user
//         const token = await jwt.sign({ userId: userExists._id }, process.env.JWT_SECRET, { expiresIn: "1day" });

//         // semd a success response
//         res.status(200).json({
//             message: "Login successful",
//             data: userExists,
//             token
//         })

//     } catch (error) {
//         console.error(error);
//         res.status(500).json({
//             message: "Error logging in User"
//         })
//     }
// };


exports.loginUser = async (req, res) => {
    try {
        validatedData = await validate(req.body, loginSchema)
        const { email, password, userName } = validatedData

        if (!email && !userName) {
            return res.status(400).json({
                message: "Please enter your email address or username"
            })
        };

        if (!password) {
            return res.status(400).json({
                message: "Please enter your password"
            })
        };
        let user;
        // find the user by either the email or the password
        if (email) {
            user = await userModel.findOne({ email: email.toLowerCase() })
        }

        if (userName) {
            user = await userModel.findOne({ userName: userName.toLowerCase() })
        }

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        };
        // compared the password with the one in the database
        const passwordCorrect = await bcrypt.compare(password, user.password);

        if (passwordCorrect === false) {
            return res.status(400).json({
                message: "Incorrect password"
            })
        };
        // check if the user is verfied
        if (user.isVerified === false) {
            return res.status(400).json({
                message: "account notverified, please check your email for the verification link"
            })
        };
        // generate a token for the user
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: "1hour" });

        res.status(200).json({
            message: "login successful",
            data: user,
            token
        })
    } catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal server error" + error.message
        })
    }
};

exports.changePassword = async (req, res) => {
    try {
        const { password, newPassword, confirmPassword } = req.body;
        const { userId } = req.user;

        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        };
        
        // verify the current password
        const passwordVerify = await bcrypt.compare(password, user.password)
        if(passwordVerify === false) {
            return res.status(404).json({
                message: "incorrect password"
            })
        }

        if(newPassword !== confirmPassword) {
            return res.status(400).json({
                message: "new password and confirm password does not match"
            })
        };
        //  encrypt the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt)

        user.password = hashedPassword;

        await user.save();

        res.status(200).json({
            message: "Password changed successfully"
        })

    } catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal server error"
        })
    }
}

exports.changeUserToAdmin = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        };

        if(user.isAdmin === true){
            return res.status(400).json({
                message: "User is already an admin"
            })
        }

        user.isAdmin = true;
        
        await user.save();

        res.status(200).json({
            message: "Change user to admin successful",
            data: user
        });
    } catch (error) {
        res.status(500).json({
            message: "Internal server error",
            data: error.message
        });
    }
};