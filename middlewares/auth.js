const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../helpers/jwt');
const User = require('../models/user');
const UnauthorizedError = require('../errors/unauthorized-error');

/** авторизация */
module.exports = (req, res, next) => {
  const { authorization } = req.headers;
  if (!authorization || !authorization.startsWith('Bearer ')) {
    next(new UnauthorizedError('Необходима авторизация'));
  }
  const token = authorization.replace('Bearer ', '');
  let payload;
  try {
    payload = jwt.verify(token, SECRET_KEY);
  } catch (err) {
    next(new UnauthorizedError('Необходима авторизация'));
  }
  req.user = payload;
  next();
  User
    .findOne({ email: payload.email })
    .then((user) => {
      if (!user) {
        next(new UnauthorizedError('Необходима авторизация'));
      }
      req.user = { id: user._id };
      res
        .status(200);
      next();
    })
    .catch(() => {
      next(new UnauthorizedError('Необходима авторизация'));
    });
};
