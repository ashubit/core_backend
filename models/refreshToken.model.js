const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    issuedAt: {
        type: Date,
        default: Date.now,
        expires: 30 * 24 * 60 * 60 // 30 days TTL
    },
    isRevoked: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

// Index for quick lookups and TTL
refreshTokenSchema.index({ token: 1 });
refreshTokenSchema.index({ userId: 1 });
refreshTokenSchema.index({ issuedAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);