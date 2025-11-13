module.exports = app => {
  const user = require("../controllers/user.controller");
  const userValidators = require("../validators/user.validator");
  const auth = require('../middlewares/auth.middleware');
  
  const router = require("express").Router();
  
  // Create a new Tutorial
  router.post("/", userValidators.create, user.create);
  
  // Retrieve all user
  router.get("/", userValidators.findAll, user.findAll);
  
  // // Retrieve a single Tutorial with id
  router.get("/:id", userValidators.id, user.findOne);
  
  // Update a Tutorial with id
  router.put("/:id", userValidators.update, user.update);
  
  // Delete a Tutorial with id
  router.delete("/:id", userValidators.id, user.delete);
  router.get('/me', auth.authenticate, user.profile); 
  //Get is not working ?
  // router.post('/me', auth.authenticate, user.profile);

     /**
     * Login & Signup Routes
     */
  router.post("/login", userValidators.login, user.login);
  router.post("/signup", userValidators.register, user.register);

  // Protected route: get current authenticated user's profile
         
  app.use('/api/v1', router);
    
  };