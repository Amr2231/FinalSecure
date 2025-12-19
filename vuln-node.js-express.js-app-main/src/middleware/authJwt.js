const jwt = require("jsonwebtoken");
const config = require("./../config");
const db = require("./../orm");
const User = db.user;

// Simple auth middleware - verify user is authenticated
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

verifyToken = (req, res, next) => {
  let token = req.headers["Token"];
  if (!token) {
    return res.status(403).send({
      message: "No token provided!"
    });
  }
  try {
    const decoded = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
      audience: 'vuln-app',
      issuer: 'vuln-app'
    });
    req.userId = decoded.id;
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({
      message: "Unauthorized!"
    });
  }
};

isAdmin = (req, res, next) => {
  User.findByPk(req.userId).then(user => {
    user.getRoles().then(roles => {
      for (let i = 0; i < roles.length; i++) {
        if (roles[i].name === "admin") {
          next();
          return;
        }
      }
      res.status(403).send({
        message: "Require Admin Role!"
      });
      return;
    });
  });
};


const authJwt = {
  verifyToken: verifyToken,
  isAdmin: isAdmin,
  requireAuth: requireAuth,
  requireAdmin: requireAdmin,
  isModerator: isModerator,
};
module.exports = authJwt;

