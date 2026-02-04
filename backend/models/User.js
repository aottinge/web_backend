const { ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');

// ============================================
// Fonctions Helper pour les utilisateurs
// ============================================

// Trouver un utilisateur par email
async function findUserByEmail(db, email) {
  return await db.collection('users').findOne({ email: email.toLowerCase() });
}

// Trouver un utilisateur par ID
async function findUserById(db, userId) {
  return await db.collection('users').findOne({ _id: new ObjectId(userId) });
}

// Créer un utilisateur (inscription classique email/password)
async function createUser(db, { email, password, name }) {
  // Hash du mot de passe
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const result = await db.collection('users').insertOne({
    email: email.toLowerCase(),
    password: hashedPassword,
    name,
    provider: 'local',
    createdAt: new Date()
  });

  return {
    _id: result.insertedId,
    email: email.toLowerCase(),
    name,
    provider: 'local',
    createdAt: new Date()
  };
}

// Comparer le mot de passe
async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

// ============================================
// Fonctions Helper pour Google OAuth
// ============================================

// Trouver un utilisateur par son Google ID
async function findUserByGoogleId(db, googleId) {
  return await db.collection('users').findOne({ googleId });
}

// Créer un utilisateur depuis Google OAuth
async function createUserFromGoogle(db, { googleId, email, name, picture }) {
  const result = await db.collection('users').insertOne({
    googleId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'google',
    createdAt: new Date()
  });

  return {
    _id: result.insertedId,
    googleId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'google',
    createdAt: new Date()
  };
}

// Trouver un utilisateur par son Discord ID
async function findUserByDiscordId(db, discordId) {
  return await db.collection('users').findOne({ discordId });
}

// Créer un utilisateur depuis Discord OAuth
async function createUserFromDiscord(db, { discordId, email, name, picture }) {
  const result = await db.collection('users').insertOne({
    discordId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'discord',
    createdAt: new Date()
  });

  return {
    _id: result.insertedId,
    discordId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'discord',
    createdAt: new Date()
  };
}

// Trouver un utilisateur par son Microsoft ID
async function findUserByMicrosoftId(db, microsoftId) {
	return db.collection('users').findOne({ microsoftId });
}

// Créer un utilisateur depuis Microsoft OAuth
async function createUserFromMicrosoft(db, { microsoftId, email, name, picture }) {
	const result = await db.collection('users').insertOne({
		microsoftId,
		email: email ? email.toLowerCase() : null,
		name,
		picture,
		provider: 'microsoft',
		createdAt: new Date()
	});

	return {
		_id: result.insertedId,
		microsoftId,
		email: email ? email.toLowerCase() : null,
		name,
		picture,
		provider: 'microsoft',
		createdAt: new Date()
	};
}

module.exports = {
  findUserByEmail,
  findUserById,
  createUser,
  comparePassword,
  findUserByGoogleId,
  createUserFromGoogle,
  findUserByDiscordId,
  createUserFromDiscord,
  findUserByMicrosoftId,
  createUserFromMicrosoft
};
