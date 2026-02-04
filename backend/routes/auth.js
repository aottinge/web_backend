const express = require("express");
const jwt = require("jsonwebtoken");
const passport = require("../config/passport");
const {
  findUserByEmail,
  findUserById,
  createUser,
  comparePassword,
} = require("../models/User");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// Fonction pour générer un JWT
const generateToken = (userId) => {
  return jwt.sign({ userId: userId.toString() }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });
};

// POST /auth/register - Inscription
router.post("/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const db = req.app.locals.db;

    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({
        error: "Données manquantes",
        message: "Email, mot de passe et nom sont requis",
      });
    }

    // Validation password
    if (password.length < 6) {
      return res.status(400).json({
        error: "Mot de passe invalide",
        message: "Le mot de passe doit contenir au moins 6 caractères",
      });
    }

    // Vérifier si l'email existe déjà
    const existingUser = await findUserByEmail(db, email);
    if (existingUser) {
      return res.status(409).json({
        error: "Email déjà utilisé",
        message: "Un compte existe déjà avec cet email",
      });
    }

    // Créer l'utilisateur
    const user = await createUser(db, { email, password, name });

    // Générer le token
    const token = generateToken(user._id);

    res.status(201).json({
      message: "Compte créé avec succès",
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        provider: user.provider,
      },
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || "1h",
    });
  } catch (error) {
    console.error("Erreur inscription:", error);
    res.status(500).json({
      error: "Erreur serveur",
      message: error.message,
    });
  }
});

// POST /auth/login - Connexion
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = req.app.locals.db;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        error: "Données manquantes",
        message: "Email et mot de passe requis",
      });
    }

    // Trouver l'utilisateur
    const user = await findUserByEmail(db, email);
    if (!user) {
      return res.status(401).json({
        error: "Identifiants invalides",
        message: "Email ou mot de passe incorrect",
      });
    }

    // Vérifier le mot de passe
    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Identifiants invalides",
        message: "Email ou mot de passe incorrect",
      });
    }

    // Générer le token JWT
    const token = generateToken(user._id);

    res.json({
      message: "Connexion réussie",
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        provider: user.provider,
        picture: user.picture,
      },
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || "1h",
    });
  } catch (error) {
    console.error("Erreur login:", error);
    res.status(500).json({
      error: "Erreur serveur",
      message: error.message,
    });
  }
});

// GET /api/auth/profile - Profil utilisateur (protégé)
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    res.json({
      message: "Profil utilisateur",
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({
      error: "Erreur serveur",
      message: error.message,
    });
  }
});

// GET /auth/users - Liste des utilisateurs (debug)
router.get("/users", async (req, res) => {
  try {
    const db = req.app.locals.db;
    const users = await db
      .collection("users")
      .find({}, { projection: { password: 0 } })
      .toArray();

    res.json({
      message: "Liste des utilisateurs",
      count: users.length,
      users,
    });
  } catch (error) {
    res.status(500).json({
      error: "Erreur serveur",
      message: error.message,
    });
  }
});

// ============================================
// TODO 2: Routes OAuth Google
// ============================================
// Instructions:
// 1. Créer une route GET '/google' qui :
//    - Utilise passport.authenticate('google', { ... })
//    - Configure les options :
//      * scope: ['profile', 'email']
//      * session: false (IMPORTANT : stateless JWT)
//    - Cette route redirige l'utilisateur vers Google pour authentification
//
// 2. Créer une route GET '/google/callback' qui :
//    - Utilise passport.authenticate('google', { session: false, failureRedirect: ... })
//    - Ajoute un handler (req, res) => { ... } après l'authentification
//    - Dans le handler :
//      * Récupérer l'utilisateur authentifié depuis req.user
//      * Générer un JWT avec generateToken(req.user._id)
//      * Rediriger vers le frontend : `${process.env.FRONTEND_URL}/auth/callback?token=${token}`
//      * En cas d'erreur, rediriger vers : `${process.env.FRONTEND_URL}/login?error=token_generation_failed`
//
// Documentation Passport : https://www.passportjs.org/concepts/authentication/oauth/
// =============================================================================

// Route d'init Google OAuth
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);

// Route d'init Microsoft OAuth
router.get(
  "/microsoft",
  passport.authenticate("microsoft", {
    scope: ["user.read"],
    session: false,
  }),
);

// Route d'init Discord OAuth
router.get(
  "/discord",
  passport.authenticate("discord", {
    scope: ["identify", "email"],
    session: false,
  }),
);

// Callback Google OAuth
router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_auth_failed`,
  }),
  (req, res) => {
    try {
      const token = generateToken(req.user._id);
      const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(token)}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      const errorUrl = `${process.env.FRONTEND_URL}/login?error=token_generation_failed`;
      return res.redirect(errorUrl);
    }
  },
);

// Callback Microsoft OAuth
router.get(
  "/microsoft/callback",
  passport.authenticate("microsoft", {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=microsoft_auth_failed`,
  }),
  (req, res) => {
    try {
      const token = generateToken(req.user._id);
      const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(token)}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      const errorUrl = `${process.env.FRONTEND_URL}/login?error=token_generation_failed`;
      return res.redirect(errorUrl);
    }
  },
);

// Callback Discord OAuth
router.get(
  "/discord/callback",
  passport.authenticate("discord", {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=discord_auth_failed`,
  }),
  (req, res) => {
    try {
      const token = generateToken(req.user._id);
      const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(token)}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      const errorUrl = `${process.env.FRONTEND_URL}/login?error=token_generation_failed`;
      return res.redirect(errorUrl);
    }
  },
);

module.exports = router;
