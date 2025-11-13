const mongoose = require('mongoose');

const tokenBlacklist = new mongoose.Schema({
    token: { 
        type: String, 
        required: true,
        unique: true 
    },
    expiresAt: { 
        type: Date, 
        required: true,
        index: { expires: 0 } // TTL index, will be removed when expiresAt is reached
    }
}, { timestamps: true });

module.exports = mongoose.model('TokenBlacklist', tokenBlacklist);