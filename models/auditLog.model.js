const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: false, // Allow logging of anonymous actions
        index: true
    },
    action: {
        type: String,
        required: true,
        index: true
    },
    resourceType: {
        type: String,
        required: true,
        index: true
    },
    resourceId: {
        type: mongoose.Schema.Types.ObjectId,
        required: false
    },
    details: {
        type: mongoose.Schema.Types.Mixed,
        required: false
    },
    status: {
        type: String,
        enum: ['success', 'failure', 'error'],
        required: true
    },
    ip: String,
    userAgent: String,
    method: String,
    path: String,
    sessionId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'UserSession',
        required: false
    }
}, {
    timestamps: true
});

// Indexes for common queries
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ action: 1, resourceType: 1 });
auditLogSchema.index({ userId: 1, createdAt: -1 });

// Automatically expire old logs after 90 days
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

module.exports = mongoose.model('AuditLog', auditLogSchema);