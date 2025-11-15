/**
 * User Routes Module
 * Defines authentication and CRUD routes for user management.
 * @param {Object} app - Express application instance
 */
module.exports = app => {
  const user = require("../controllers/user.controller");
  const userValidators = require("../validators/user.validator");
  const auth = require('../middlewares/auth.middleware');

  const router = require("express").Router();

  /**
   * Authentication Routes
   */
  router.post("/login", userValidators.login, user.login);
  router.post("/signup", userValidators.register, user.register);
  router.get('/me', auth.authenticate, user.profile);

  /**
   * User CRUD Routes
   */
  router.post("/", userValidators.create, user.create);
  router.get("/", userValidators.findAll, user.findAll);
  router.get("/:id", userValidators.id, user.findOne);
  router.put("/:id", userValidators.update, user.update);
  router.delete("/:id", userValidators.id, user.delete);

  app.use('/api/v1', router);
};
