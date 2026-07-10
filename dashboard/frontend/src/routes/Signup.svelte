<script>
  import { push } from 'svelte-spa-router';
  import { api } from '../lib/api.js';

  let email = '';
  let password = '';
  let error = '';
  let success = '';
  let loading = false;

  async function handleSignup() {
    loading = true;
    error = '';
    success = '';
    try {
      await api.signup(email, password);
      success = 'Account created! Waiting for admin approval.';
      setTimeout(() => push('/login'), 2000);
    } catch (e) {
      if (e.message && e.message.includes('409')) {
        error = 'Email already registered';
      } else {
        error = (e.message) || 'Signup failed';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="auth-container">
  <h1>Sign Up</h1>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if success}
    <div class="success">{success}</div>
  {/if}
  <form on:submit|preventDefault={handleSignup}>
    <input type="email" bind:value={email} placeholder="Email" required />
    <input type="password" bind:value={password} placeholder="Password (min 8 chars)" required minlength="8" />
    <button type="submit" disabled={loading}>
      {loading ? 'Creating account...' : 'Sign Up'}
    </button>
  </form>
  <p class="link">Already have an account? <a href="/login">Login</a></p>
</div>

<style>
  .auth-container { max-width: 400px; margin: 80px auto; padding: 2rem; }
  h1 { margin-bottom: 1.5rem; }
  .error { color: #e74c3c; margin-bottom: 1rem; padding: 0.75rem; background: #fdecea; border-radius: 4px; }
  .success { color: #27ae60; margin-bottom: 1rem; padding: 0.75rem; background: #eafaf1; border-radius: 4px; }
  input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
  button { width: 100%; padding: 0.75rem; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .link { text-align: center; margin-top: 1rem; }
  a { color: #3498db; }
</style>
