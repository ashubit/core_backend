const mongoose = require('mongoose');

const userSessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true,
        index: true
    },
    deviceInfo: {
        userAgent: String,
        ip: String,
        // Allow structured location (country/city/coordinates) for visualizations
        lastLocation: {
            type: Object,
            required: false
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastActivity: {
        type: Date,
        default: Date.now
    },
    refreshToken: {
        type: String,
        required: true,
        unique: true
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expires: 0 } // TTL index
    }
}, { timestamps: true });

// Compound index for quick lookups
userSessionSchema.index({ userId: 1, isActive: 1 });

module.exports = mongoose.model('UserSession', userSessionSchema);