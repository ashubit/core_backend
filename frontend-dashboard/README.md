Frontend Dashboard

This is a tiny React (Vite) dashboard that consumes the backend visualization endpoints you've added.

Prerequisites
- Node.js >= 14
- Backend server running (default: http://localhost:8081)

Quick start

```powershell
cd frontend-dashboard
npm install
npm run dev
```

What it includes
- Session stats line chart (consumes `/api/v1/visualizations/session-stats`)
- Geo-activity list (consumes `/api/v1/visualizations/geo-activity`)

Notes
- The backend allows CORS from any origin by default in your server, so the frontend should be able to fetch directly.
- You can change the backend base URL in `src/api.js`.

Next steps (optional)
- Add authentication integration (send Authorization header)
- Add nicer charts and map visualization for geo data
- Add filtering and date pickers
