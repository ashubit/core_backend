## This node project is backend of React Native project in "Git_project/React-Native/Sahil-ReactNative" 

npm test


## Security Notes
Set a strong JWT_SECRET in production
Consider adding:
Rate limiting on auth endpoints
Password complexity requirements
Email verification
Refresh tokens for better security
Monitor token blacklist collection size
Add logging for security events

## New Features Overview
Refresh Token System:

Access tokens now expire in 1 hour
Refresh tokens valid for 30 days
Refresh tokens stored in HTTP-only cookies
Token rotation on refresh
Automatic cleanup of expired tokens
Rate Limiting:

API-wide: 100 requests per 15 minutes per IP
Auth endpoints: 5 attempts per hour per IP
User creation: 3 accounts per hour per IP
Enhanced Role-Based Access:

Granular permissions: read:own, read:any, create:any, etc.
Resource ownership verification
Admin-only routes and statistics
Hierarchical permission structure
Security Improvements:

HTTP-only cookies for refresh tokens
Token rotation on refresh
Comprehensive token revocation
Request limiting against brute force
Permission-based access control

Session Management:

View all active sessions with device info
Revoke individual sessions
Revoke all sessions except current
Auto-cleanup of expired sessions
Device and location tracking
Audit Logging:

Automatic logging of all API requests
Tracks user actions, endpoints, and outcomes
Captures IP and user agent info
Sanitizes sensitive data
Admin-only audit log access
Filtering by user, action, and date range
Automatic log rotation (90 days)
Security Enhancements:

Session-aware token management
Device fingerprinting
Location tracking (if using Cloudflare or add GeoIP)
Audit trail for security events
Automatic cleanup of old data

Enhanced Session Tracking:

Last action timestamp
Path and method tracking
Device info updates
Location history
IP-based Location Detection:

GeoIP lookup
Country/region/city tracking
Coordinates for mapping
Last known location per session
Detailed Audit Reports:

Activity timeline
Security event analysis
Geographic distribution
User behavior patterns
Device usage statistics
Testing:

Comprehensive test suite
Authentication tests
Session management tests
Audit logging verification
Location tracking tests



## Visualization Endpoints:
Activity heatmap showing usage patterns by hour/day
Geospatial visualization of login locations
Session statistics and trends
Device distribution analytics
Active user trends
## Anomaly Detection:
Detection of suspicious login patterns
Location-based anomaly detection
Unusual access time detection
Multiple failed login attempts monitoring
Concurrent session analysis
User behavior pattern analysis
Risk score calculation
Enhanced Device Fingerprinting:
Detailed browser and OS detection
Device type identification
Screen resolution tracking
Language preferences
Timezone information
Platform details
IP and location tracking
You can now:

## View activity visualizations at /api/v1/visualizations/*
## Monitor security anomalies at /api/v1/security/*
Track user risk scores and security status
Get detailed device and behavioral analytics
The system will automatically:

Track and analyze user behavior patterns
Detect suspicious activities
Calculate risk scores
Enforce additional security measures when needed
```markdown
# Working Backend (Node/Express)

Backend for the React Native project. This README documents the newly added visualization, anomaly detection, and enhanced device fingerprinting features and shows how to use them.

Prerequisites
- Node.js >= 14
- MongoDB running and reachable (configured via `MONGO_URI` in `.env`)
- Environment variables set (see `.env` or `.env.example`)

Run locally

```powershell
# install deps
npm install

# start server (ensure MongoDB is running)
node server.js
```

Security notes (short)
- Set a strong `JWT_SECRET` in production.
- Keep `NODE_ENV=production` in production and enable HTTPS.
- Review `AUDIT_LOG_RETENTION_DAYS` and token cleanup policies.

-- New/Important Features --

1) Visualization endpoints
- Heatmap, geo-activity, session statistics, device distribution, active user trends.

2) Anomaly detection / Security endpoints
- Detects rapid location changes, multiple failed logins, concurrent sessions from different countries, unusual access hours, and computes a user risk score.

3) Enhanced device fingerprinting
- Parses user-agent, collects platform/timezone/language hints and stores device info per session.

API endpoints (admin-only unless noted)

- GET /api/v1/visualizations/heatmap
	- Query: `start`, `end` (ISO date strings), `userId` (optional)
	- Returns aggregated counts by hour/day for activity heatmap.

- GET /api/v1/visualizations/geo-activity
	- Query: `start`, `end`
	- Returns grouped locations with counts and coordinates.

- GET /api/v1/visualizations/session-stats
	- Query: `start`, `end`
	- Returns time-series of total/active sessions and unique users per day.

- GET /api/v1/visualizations/device-distribution
	- Query: `start`, `end`
	- Returns browser/os/device distribution with counts.

- GET /api/v1/visualizations/user-trends
	- Query: `days` (defaults to 30)
	- Returns active user trends over the requested window.

- GET /api/v1/security/user/:userId/anomalies (admin)
	- Returns detected behavior anomalies for a user (recent period analysis).

- GET /api/v1/security/user/:userId/risk-score (admin)
	- Returns calculated risk score and contributing factors.

- GET /api/v1/security/my-security-status (authenticated user)
	- Returns your anomalies, risk score, and whether additional verification is required for your session.

Authentication & Roles
- Most endpoints require JWT auth and the `admin` role (see `middlewares/roles.middleware`).
- Use the `Authorization: Bearer <token>` header for protected endpoints. Some actions also rely on the session cookie (`refreshToken`).

Example requests (PowerShell & curl)

PowerShell (get heatmap):

```powershell
$token = '<ACCESS_TOKEN>'
Invoke-RestMethod -Uri 'http://localhost:8081/api/v1/visualizations/heatmap?start=2025-10-01&end=2025-11-09' -Headers @{ Authorization = "Bearer $token" } -Method Get | ConvertTo-Json
```

curl (get geo-activity):

```bash
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" \
	'http://localhost:8081/api/v1/visualizations/geo-activity?start=2025-10-01&end=2025-11-09'
```

Get current user's security status (authenticated user):

```bash
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8081/api/v1/security/my-security-status
```

Example response shapes (abridged)

- Heatmap item
```json
{ "_id": { "hour": 14, "dayOfWeek": 1 }, "count": 123 }
```

- Geo-activity item
```json
{ "location": { "country": "US", "city": "San Francisco", "coordinates": [37.77, -122.41] }, "count": 42, "uniqueUsers": 10 }
```

- Risk score
```json
{ "base": 100, "factors": [{ "name": "failed_logins", "impact": -20, "count": 2 }], "finalScore": 80 }
```

Notes & operational guidance
- The system stores device info and last known geo location per session. GeoIP uses the `geoip-lite` DB (ensure it's up-to-date if needed).
- Anomaly detection heuristics are intentionally conservative; tune thresholds in `services/anomaly.service.js` to fit your risk appetite.
- If you expect high traffic/large datasets, create indexes on `AuditLog.createdAt`, `AuditLog.userId`, and `UserSession.createdAt`/`deviceInfo.lastLocation.country` to speed aggregation.

Next steps / optional work I can do for you
- Add Jest + Supertest integration tests for visualization/security routes (requires DB mocking or a test DB).
- Add pagination and date range validation for very large responses.
- Add a small frontend dashboard that consumes `/api/v1/visualizations/*` endpoints for charts.

If you want, I can also add example Jest tests for one visualization endpoint — say the `session-stats` route — using an in-memory MongoDB instance. Reply with which option you prefer.
```




## Exporting a session:
Open the specific chat session you want to export in the Chat view.
Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P on macOS).
Type "Chat: Export Chat..." and select the command.
Choose a location to save the exported JSON file. This file contains the prompts and responses from that session.
## Importing a session:
Open the Command Palette.
Type "Chat: Import Chat..." and select the command.
Select the JSON file you previously exported or a history file from another workspace. 


