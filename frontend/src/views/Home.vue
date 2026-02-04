<template>
  <div>
    <nav>
      <h2>🏠 Accueil</h2>
      <button @click="handleLogout">Déconnexion</button>
    </nav>

    <div class="container">
      <h1>Bienvenue {{ user?.name }} !</h1>

      <div v-if="error" class="error">{{ error }}</div>

      <div class="user-info" v-if="profile">
        <h2>📋 Profil utilisateur</h2>
        <p><strong>ID:</strong> {{ profile._id }}</p>
        <p><strong>Nom:</strong> {{ profile.name }}</p>
        <p><strong>Email:</strong> {{ profile.email }}</p>
        <p><strong>Membre depuis:</strong> {{ formatDate(profile.createdAt) }}</p>
      </div>

      <div class="jwt-info">
        <h3>🔑 Informations JWT</h3>
        <p><strong>Token stocké dans:</strong> <code>localStorage.getItem('accessToken')</code></p>
        <p><strong>Token utilisé:</strong> Header <code>Authorization: Bearer [TOKEN]</code></p>
        <p><strong>Expiration:</strong> {{ tokenExpiry }}</p>
        <p><strong>Pas de session serveur:</strong> ✅ Stateless</p>

        <div style="margin-top: 15px; padding: 10px; background: white; border-radius: 5px; word-break: break-all; font-size: 12px;">
          <strong>Token (tronqué):</strong><br>
          <code>{{ truncatedToken }}</code>
        </div>
      </div>

      <button @click="fetchProfile" style="margin-top: 20px; background: #4caf50;">
        🔄 Recharger le profil
      </button>
    </div>
  </div>
</template>

<script>
import { authService } from '../services/api'

export default {
  name: 'Home',
  data() {
    return {
      user: null,
      profile: null,
      error: null,
      tokenExpiry: '1 heure'
    }
  },
  computed: {
    truncatedToken() {
      const token = localStorage.getItem('accessToken')
      if (!token) return 'Aucun token'
      return token.substring(0, 50) + '...' + token.substring(token.length - 20)
    }
  },
  mounted() {
    this.user = authService.getCurrentUser()
    this.fetchProfile()
  },
  methods: {
    async fetchProfile() {
      this.error = null
      try {
        const response = await authService.getProfile()
        this.profile = response.user
      } catch (err) {
        this.error = err.response?.data?.message || 'Erreur lors du chargement du profil'
      }
    },
    handleLogout() {
      authService.logout()
      this.$router.push('/login')
    },
    formatDate(dateString) {
      return new Date(dateString).toLocaleString('fr-FR')
    }
  }
}
</script>
