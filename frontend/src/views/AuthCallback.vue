<template>
  <div class="callback-container">
    <div class="spinner"></div>
    <p>🔄 Connexion en cours...</p>
    <p v-if="error" class="error">{{ error }}</p>
  </div>
</template>

<script>
export default {
  name: 'AuthCallback',
  data() {
    return {
      error: null
    }
  },
  mounted() {
    // Récupérer le token depuis l'URL (passé par le backend)
    const urlParams = new URLSearchParams(window.location.search)
    const token = urlParams.get('token')

    if (token) {
      // Stocker le token dans localStorage (comme pour login classique)
      localStorage.setItem('accessToken', token)

      // Rediriger vers la page d'accueil
      setTimeout(() => {
        this.$router.push('/home')
      }, 500)
    } else {
      // Pas de token = erreur
      this.error = 'Aucun token reçu. Redirection vers la page de connexion...'
      setTimeout(() => {
        this.$router.push('/login')
      }, 2000)
    }
  }
}
</script>

<style scoped>
.callback-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  text-align: center;
  color: #333;
}

.spinner {
  width: 50px;
  height: 50px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #2563eb;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.callback-container p {
  font-size: 1.2rem;
  margin: 0.5rem 0;
}

.error {
  color: #dc2626;
  font-weight: 500;
}
</style>
