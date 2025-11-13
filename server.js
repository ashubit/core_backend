require('dotenv').config();
const express = require("express");
const cors = require("cors");
const cookieParser = require('cookie-parser');
const { auditLogger } = require('./middlewares/audit.middleware');
const { activityTracker } = require('./middlewares/activity.middleware');

const app = express();

const db = require("./models");
db.mongoose
  .connect(db.url)
  .then(() => {
    console.log("Connected to the database!");
  })
  .catch(err => {
    console.log("Cannot connect to the database!", err);
    process.exit();
  });

var corsOptions = {
  origin: "http://localhost:8081"
};

app.use(cors("*"));

// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Add audit logging and activity tracking middleware
// app.use(auditLogger);
// app.use(activityTracker);

// Reports routes
app.use('/api/v1/reports', require('./routes/reports.routes'));

// Visualization routes
app.use('/api/v1/visualizations', require('./routes/visualization.routes'));

// Security routes
app.use('/api/v1/security', require('./routes/security.routes'));

// simple route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to application." });
});

require("./routes/tutorial.routes")(app);

// set port, listen for requests
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});

// (No module.exports) - server starts immediately