const mongoose = require('mongoose');
const files = new mongoose.Schema({
    fileName: {
        required: true,
        type: String
    },
    fileHash: {
        required: true,
        type: String
    },
    blockedStatus: {
        required: true,
        type: Boolean
    },
    userID: {
        required: false,
        type: String
    },
    date:{
        required:true,
        type:String
    },
    filesize:{
        required:true,
        type:String
    }
})

module.exports = mongoose.model('Files', files)
