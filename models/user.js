const mongoose = require("mongoose");

const userSChema = new mongoose.Schema({
    
    fullName: {
        type: String,
        require: true
    },

    email: {
        type: String,
        required: true,
        lowercase: true
    },

    userName: {
        type: String,
        lowercase: true
    },

    password: {
        type: String,
    },

    gender: {
        type: String,
        enum: ["Male", "Female"]
    },
    isVerified: {
        type: Boolean,
        default: false
    },

    isAdmin: {
        type: Boolean,
        default: false
    },
    scoresId: {
        type: mongoose.SchemaTypes.ObjectId,
        ref: "SCores"
    }

}, { timestamps: true })

const userModel = mongoose.model("Users", userSChema);

module.exports = userModel