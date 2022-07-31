const mongoose = require('mongoose');
const users = new mongoose.Schema({
    userName: {
        required: true,
        type: String
    },
    password: {
        required: true,
        type: String
    },
    token: {
        required: false,
        type: String
    },
    isAdmin: {
        required: false,
        type: Boolean
    }
})

module.exports = mongoose.model('UserDB', users)

