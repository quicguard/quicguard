<script>
  import Router from 'svelte-spa-router';
  import Login from './routes/Login.svelte';
  import Signup from './routes/Signup.svelte';
  import Dashboard from './routes/Dashboard.svelte';

  const routes = {
    '/login': Login,
    '/signup': Signup,
    '/dashboard': Dashboard,
    '*': Login,
  };
</script>

<Router {routes} />

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f6fa;
    color: #2c3e50;
  }
</style>
