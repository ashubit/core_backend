const { body, param, query, validationResult } = require('express-validator');

const validate = (checks) => {
  return [
    ...checks,
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      next();
    },
  ];
};

exports.id = validate([
  param('id').isMongoId().withMessage('Invalid id'),
]);

exports.create = validate([
  body('name').notEmpty().withMessage('Name is required').isLength({ max: 60 }).withMessage('Name too long'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('mobile').notEmpty().withMessage('Mobile is required').isLength({ min: 10, max: 10 }).withMessage('Invalid mobile'),
]);

exports.update = validate([
  param('id').isMongoId().withMessage('Invalid id'),
  body('name').optional().isLength({ max: 100 }).withMessage('Name too long'),
  body('email').optional().isEmail().withMessage('Valid email is required'),
  body('mobile').optional().isLength({ min: 10, max: 10 }).withMessage('Invalid mobile'),
]);

exports.findAll = validate([
  query('q').optional().isString().isLength({ max: 100 }).withMessage('Query too long'),
  query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Limit must be an integer between 1 and 1000'),
]);

exports.login = validate([
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required'),
]);

exports.register = validate([
  body('name').notEmpty().withMessage('Name is required').isLength({ max: 100 }).withMessage('Name too long'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('mobile').notEmpty().withMessage('Mobile is required').isLength({ max:10 }).withMessage('Invalid mobile'),
]);
