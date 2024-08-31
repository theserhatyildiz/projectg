const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name: {
        type: String, 
        required: true
    },
    email: {
        type: String,  
        required: true 
    },
    password: {
        type: String,  
        required: true
    },
    startDate: {
        type: Date,
        default: null // Bu kisi kilo takibi icin yeni bir baslangic tarihi secmede kullaniliyor
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    emailToken: {
        type: String,
    }
},{timestamps:true})

const userModel = mongoose.model("users",userSchema);

module.exports = userModel;