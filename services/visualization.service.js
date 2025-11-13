const UserSession = require('../models/userSession.model');
const AuditLog = require('../models/auditLog.model');
const User = require('../models/user.model');

class VisualizationService {
    // Get activity heatmap data (activity by hour and day of week)
    async getActivityHeatmap(startDate, endDate, userId = null) {
        const match = {
            createdAt: { $gte: new Date(startDate), $lte: new Date(endDate) }
        };
        if (userId) match.userId = userId;

        const heatmapData = await AuditLog.aggregate([
            { $match: match },
            {
                $project: {
                    hour: { $hour: "$createdAt" },
                    dayOfWeek: { $dayOfWeek: "$createdAt" },
                }
            },
            {
                $group: {
                    _id: {
                        hour: "$hour",
                        dayOfWeek: "$dayOfWeek"
                    },
                    count: { $sum: 1 }
                }
            }
        ]);

        return heatmapData;
    }

    // Get geospatial activity visualization data
    async getGeoActivityData(startDate, endDate) {
        const geoData = await UserSession.aggregate([
            {
                $match: {
                    'deviceInfo.lastLocation': { $exists: true },
                    createdAt: { $gte: new Date(startDate), $lte: new Date(endDate) }
                }
            },
            {
                $group: {
                    _id: {
                        country: '$deviceInfo.lastLocation.country',
                        city: '$deviceInfo.lastLocation.city',
                        coordinates: '$deviceInfo.lastLocation.ll'
                    },
                    count: { $sum: 1 },
                    users: { $addToSet: '$userId' }
                }
            },
            {
                $project: {
                    location: '$_id',
                    count: 1,
                    uniqueUsers: { $size: '$users' }
                }
            }
        ]);

        return geoData;
    }

    // Get user session statistics
    async getSessionStats(startDate, endDate) {
        return await UserSession.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(startDate), $lte: new Date(endDate) }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
                    },
                    totalSessions: { $sum: 1 },
                    activeSessions: {
                        $sum: { $cond: ["$isActive", 1, 0] }
                    },
                    uniqueUsers: { $addToSet: "$userId" }
                }
            },
            {
                $project: {
                    date: "$_id",
                    totalSessions: 1,
                    activeSessions: 1,
                    uniqueUsers: { $size: "$uniqueUsers" }
                }
            },
            { $sort: { date: 1 } }
        ]);
    }

    // Get browser/device distribution
    async getDeviceDistribution(startDate, endDate) {
        return await UserSession.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(startDate), $lte: new Date(endDate) }
                }
            },
            {
                $group: {
                    _id: {
                        browser: '$deviceInfo.browser',
                        os: '$deviceInfo.os',
                        device: '$deviceInfo.device'
                    },
                    count: { $sum: 1 },
                    users: { $addToSet: '$userId' }
                }
            },
            {
                $project: {
                    browser: '$_id.browser',
                    os: '$_id.os',
                    device: '$_id.device',
                    count: 1,
                    uniqueUsers: { $size: '$users' }
                }
            },
            { $sort: { count: -1 } }
        ]);
    }

    // Get active user trends
    async getActiveUserTrends(days = 30) {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        return await UserSession.aggregate([
            {
                $match: {
                    lastActivity: { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$lastActivity" }
                    },
                    uniqueUsers: { $addToSet: "$userId" },
                    totalActivity: { $sum: 1 }
                }
            },
            {
                $project: {
                    date: "$_id",
                    uniqueUsers: { $size: "$uniqueUsers" },
                    totalActivity: 1
                }
            },
            { $sort: { date: 1 } }
        ]);
    }
}

module.exports = new VisualizationService();