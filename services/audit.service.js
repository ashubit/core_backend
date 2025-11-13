const AuditLog = require('../models/auditLog.model');
const UserSession = require('../models/userSession.model');

class AuditService {
    static async getActivityReport(startDate, endDate, userId = null) {
        const match = {
            createdAt: {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            }
        };
        
        if (userId) match.userId = userId;

        return AuditLog.aggregate([
            { $match: match },
            {
                $group: {
                    _id: {
                        date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                        action: "$action",
                        status: "$status"
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $group: {
                    _id: "$_id.date",
                    actions: {
                        $push: {
                            action: "$_id.action",
                            status: "$_id.status",
                            count: "$count"
                        }
                    },
                    totalCount: { $sum: "$count" }
                }
            },
            { $sort: { _id: 1 } }
        ]);
    }

    static async getSecurityReport(startDate, endDate) {
        return AuditLog.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: new Date(startDate),
                        $lte: new Date(endDate)
                    },
                    action: {
                        $in: ['login', 'logout', 'failed_login', 'password_reset', 'session_revoked']
                    }
                }
            },
            {
                $group: {
                    _id: {
                        date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                        action: "$action"
                    },
                    uniqueUsers: { $addToSet: "$userId" },
                    uniqueIPs: { $addToSet: "$ip" },
                    count: { $sum: 1 }
                }
            },
            {
                $project: {
                    date: "$_id.date",
                    action: "$_id.action",
                    uniqueUserCount: { $size: "$uniqueUsers" },
                    uniqueIPCount: { $size: "$uniqueIPs" },
                    totalCount: "$count"
                }
            },
            { $sort: { date: 1, action: 1 } }
        ]);
    }

    static async getLocationReport(startDate, endDate) {
        return UserSession.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: new Date(startDate),
                        $lte: new Date(endDate)
                    }
                }
            },
            {
                $group: {
                    _id: "$deviceInfo.lastLocation.country",
                    sessions: { $sum: 1 },
                    uniqueUsers: { $addToSet: "$userId" }
                }
            },
            {
                $project: {
                    country: "$_id",
                    sessions: 1,
                    uniqueUsers: { $size: "$uniqueUsers" }
                }
            },
            { $sort: { sessions: -1 } }
        ]);
    }

    static async getUserActivityTimeline(userId, limit = 100) {
        return AuditLog.find({ userId })
            .sort({ createdAt: -1 })
            .limit(limit)
            .populate('sessionId', 'deviceInfo')
            .lean();
    }
}

module.exports = AuditService;