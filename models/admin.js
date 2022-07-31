const mongoose = require('mongoose');
const admin = new mongoose.Schema({
    requestId: {
        required: true,
        type: String
    },
    fileName: {
        required: true,
        type: String
    },
    reason: {
        required: true,
        type: String
    },
    resolved:{
        required:true,
        type:Boolean
    }
})

module.exports = mongoose.model('adminRequest', admin)