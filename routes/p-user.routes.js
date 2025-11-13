module.exports = app => {
  const user = require("../controllers/user.controller");
  const userValidators = require("../validators/user.validator");
  const auth = require('../middlewares/auth.middleware');
  const { hasRole, hasPermission } = require('../middlewares/roles.middleware');
  const { apiLimiter, authLimiter, createUserLimiter } = require('../middlewares/rateLimiter.middleware');
  
  const router = require("express").Router();

  /**
   * Public Routes
   */
  router.post("/login", authLimiter, userValidators.login, user.login);
  router.post("/signup", createUserLimiter, userValidators.register, user.register);
  router.post("/refresh-token", authLimiter, user.refresh);

  // Apply rate limiting to all API routes
  router.use(apiLimiter);
  
  /**
   * Protected Routes - Require Authentication
   */
  // User profile and auth management
  router.get('/meee', auth.authenticate, user.profile);
  router.post('/logout', auth.authenticate, user.logout);
  
  // Protected user routes with permission checks
  router.get("/", 
    auth.authenticate, 
    hasPermission('read:any'),
    userValidators.findAll, 
    user.findAll
  );

  router.get("/:id", 
    auth.authenticate,
    hasPermission('read:own'),
    userValidators.id,
    user.findOne
  );
  
  /**
   * Admin Only Routes
   */
  router.post("/", 
    auth.authenticate, 
    hasRole(['admin']), 
    hasPermission('create:any'),
    userValidators.create, 
    user.create
  );

  router.put("/:id", 
    auth.authenticate,
    hasPermission('update:any'),
    userValidators.update,
    user.update
  );

  router.delete("/:id", 
    auth.authenticate,
    hasPermission('delete:any'),
    userValidators.id,
    user.delete
  );

  // Admin specific routes
  router.get("/admin/stats",
    auth.authenticate,
    hasRole(['admin']),
    hasPermission('manage:users'),
    user.getStats
  );

  app.use('/api/v1', router);
};