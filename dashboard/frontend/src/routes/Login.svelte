<script>
  import { push } from 'svelte-spa-router';
  import { api } from '../lib/api.js';
  import { authStore } from '../lib/auth.js';

  let email = '';
  let password = '';
  let error = '';
  let loading = false;

  async function handleLogin() {
    loading = true;
    error = '';
    try {
      const res = await api.login(email, password);
      authStore.login(res.token, res.user);
      push('/dashboard');
    } catch (e) {
      if (e.message && e.message.includes('403')) {
        error = 'Account not approved yet. Please wait for admin approval.';
      } else {
        error = (e.message) || 'Login failed';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="auth-container">
  <h1>Login</h1>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  <form on:submit|preventDefault={handleLogin}>
    <input type="email" bind:value={email} placeholder="Email" required />
    <input type="password" bind:value={password} placeholder="Password" required />
    <button type="submit" disabled={loading}>
      {loading ? 'Logging in...' : 'Login'}
    </button>
  </form>
  <p class="link">Don't have an account? <a href="/signup">Sign up</a></p>
</div>

<style>
  .auth-container { max-width: 400px; margin: 80px auto; padding: 2rem; }
  h1 { margin-bottom: 1.5rem; }
  .error { color: #e74c3c; margin-bottom: 1rem; padding: 0.75rem; background: #fdecea; border-radius: 4px; }
  input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
  button { width: 100%; padding: 0.75rem; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .link { text-align: center; margin-top: 1rem; }
  a { color: #3498db; }
</style>
