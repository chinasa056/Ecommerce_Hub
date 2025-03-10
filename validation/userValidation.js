const joi = require("joi")

exports.reqisterUserSchema = joi.object().keys({
    fullName: joi.string().min(3).max(40).required(),
    email: joi.string().trim().email().required(),
    password: joi.string().trim().required(),
    gender: joi.string().trim().valid("Female", "Male").required(),
    userName: joi.string().trim().required()

})

exports.loginSchema = joi.object().keys({
    email: joi.string().trim().min(3).max(40).email().required(),
    password: joi.string().trim().required()
})