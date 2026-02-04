const jwt = require('jsonwebtoken');
const { findUserById } = require('../models/User');

// Middleware pour vérifier le JWT
const authenticateToken = async (req, res, next) => {
  try {
    // Extraire le token du header Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (!token) {
      return res.status(401).json({
        error: 'Access token requis',
        message: 'Vous devez être connecté pour accéder à cette ressource'
      });
    }

    // Vérifier et décoder le token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Récupérer l'utilisateur depuis MongoDB (driver natif)
    const db = req.app?.locals?.db;
    if (!db) {
      return res.status(500).json({
        error: 'Base de données indisponible',
        message: 'db non initialisée dans app.locals'
      });
    }

    const user = await findUserById(db, decoded.userId);

    if (!user) {
      return res.status(404).json({
        error: 'Utilisateur non trouvé',
        message: 'Ce compte n\'existe plus'
      });
    }

  // Nettoyer et ajouter l'utilisateur à la requête
  if (user.password) delete user.password;
  req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expiré',
        message: 'Votre session a expiré, veuillez vous reconnecter'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        error: 'Token invalide',
        message: 'Le token fourni est invalide'
      });
    }

    res.status(500).json({
      error: 'Erreur serveur',
      message: error.message
    });
  }
};

module.exports = { authenticateToken };
