<template>
  <div class="container">
    <h1>🎓 Inscription</h1>

    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="success" class="success">{{ success }}</div>

    <form @submit.prevent="handleRegister">
      <div class="form-group">
        <label for="name">Nom complet</label>
        <input
          type="text"
          id="name"
          v-model="form.name"
          placeholder="Jean Dupont"
          required
        />
      </div>

      <div class="form-group">
        <label for="email">Email</label>
        <input
          type="email"
          id="email"
          v-model="form.email"
          placeholder="jean.dupont@example.com"
          required
        />
      </div>

      <div class="form-group">
        <label for="password">Mot de passe</label>
        <input
          type="password"
          id="password"
          v-model="form.password"
          placeholder="Min 6 caractères"
          required
          minlength="6"
        />
      </div>

      <button type="submit" :disabled="loading">
        {{ loading ? 'Inscription...' : 'S\'inscrire' }}
      </button>
    </form>

    <div class="link">
      Déjà un compte ? <router-link to="/login">Se connecter</router-link>
    </div>

    <div class="jwt-info">
      <h3>💡 JWT Demo</h3>
      <p>
        ✅ Pas de session serveur<br>
        ✅ Token stocké dans <code>localStorage</code><br>
        ✅ MongoDB pour les utilisateurs uniquement
      </p>
    </div>
  </div>
</template>

<script>
import { authService } from '../services/api'

export default {
  name: 'Register',
  data() {
    return {
      form: {
        name: '',
        email: '',
        password: ''
      },
      error: null,
      success: null,
      loading: false
    }
  },
  methods: {
    async handleRegister() {
      this.error = null
      this.success = null
      this.loading = true

      try {
        const response = await authService.register(this.form)
        this.success = response.message

        // Rediriger vers home après inscription réussie
        setTimeout(() => {
          this.$router.push('/home')
        }, 1000)
      } catch (err) {
        this.error = err.response?.data?.message || 'Erreur lors de l\'inscription'
      } finally {
        this.loading = false
      }
    }
  }
}
</script>
