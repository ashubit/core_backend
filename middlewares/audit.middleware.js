const AuditLog = require('../models/auditLog.model');
const UserSession = require('../models/userSession.model');

exports.auditLogger = async (req, res, next) => {
    // Store the original send function
    const originalSend = res.send;
    const startTime = Date.now();

    // Get basic request info
    const requestInfo = {
        ip: req.ip,
        method: req.method,
        path: req.originalUrl,
        userAgent: req.get('user-agent'),
        userId: req.user?.userId,
        sessionId: req.session?._id
    };

    // Create log entry function
    const createLog = async (status, responseBody) => {
        try {
            // Determine action and resource type from the path
            const pathParts = req.path.split('/').filter(Boolean);
            const resourceType = pathParts[1] || 'unknown';
            const action = `${req.method.toLowerCase()}:${resourceType}`;

            await AuditLog.create({
                userId: req.user?.userId,
                action,
                resourceType,
                resourceId: req.params.id,
                details: {
                    request: {
                        body: req.method !== 'GET' ? sanitizeBody(req.body) : undefined,
                        query: req.query,
                        params: req.params
                    },
                    response: sanitizeResponse(responseBody),
                    duration: Date.now() - startTime
                },
                status,
                ...requestInfo
            });
        } catch (error) {
            console.error('Audit logging failed:', error);
        }
    };

    // Override send function to intercept response
    res.send = function (body) {
        const responseBody = body;
        
        // Log based on status code
        const status = res.statusCode >= 400 ? 'failure' : 'success';
        createLog(status, responseBody);

        // Call original send
        originalSend.call(this, body);
    };

    // Handle errors
    res.on('error', (error) => {
        createLog('error', { error: error.message });
    });

    next();
};

// Helper to remove sensitive data
function sanitizeBody(body) {
    if (!body) return body;
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'pwd', 'token', 'refreshToken', 'secret'];
    
    sensitiveFields.forEach(field => {
        if (field in sanitized) {
            sanitized[field] = '[REDACTED]';
        }
    });
    
    return sanitized;
}

// Helper to sanitize response
function sanitizeResponse(body) {
    if (!body) return body;
    if (typeof body === 'string') {
        try {
            body = JSON.parse(body);
        } catch {
            return body.length > 1000 ? body.substring(0, 1000) + '...' : body;
        }
    }
    return sanitizeBody(body);
}