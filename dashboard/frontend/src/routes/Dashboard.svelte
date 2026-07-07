<script>
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { authStore } from '../lib/auth.js';
  import { api } from '../lib/api.js';

  let user = null;
  let users = [];
  let orgs = [];
  let loading = true;
  let error = '';

  let newOrgId = '';
  let newOrgName = '';
  let newOrgConfig = '{}';

  let editingOrg = null;
  let editName = '';
  let editConfig = '';

  onMount(() => {
    const unsub = authStore.subscribe(v => {
      user = v.user;
      if (!user) push('/login');
    });
    if (user) loadData();
    return unsub;
  });

  async function loadData() {
    loading = true;
    error = '';
    try {
      if (user && user.role === 'admin') {
        const [usersRes, orgsRes] = await Promise.all([
          api.admin.listUsers(),
          api.admin.listOrgs(),
        ]);
        users = usersRes.users;
        orgs = orgsRes.organizations;
      } else {
        const res = await api.orgs.list();
        orgs = res.organizations;
      }
    } catch (e) {
      error = e.message || 'Failed to load data';
    } finally {
      loading = false;
    }
  }

  async function approveUser(id) {
    try {
      await api.admin.approveUser(id);
      await loadData();
    } catch (e) {
      alert(e.message);
    }
  }

  async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    try {
      await api.admin.deleteUser(id);
      await loadData();
    } catch (e) {
      alert(e.message);
    }
  }

  async function createOrg() {
    try {
      const config = JSON.parse(newOrgConfig);
      await api.orgs.create(newOrgId, newOrgName, config);
      newOrgId = '';
      newOrgName = '';
      newOrgConfig = '{}';
      await loadData();
    } catch (e) {
      alert(e.message);
    }
  }

  function startEdit(org) {
    editingOrg = org;
    editName = org.name;
    editConfig = JSON.stringify(org.config, null, 2);
  }

  async function saveEdit() {
    if (!editingOrg) return;
    try {
      await api.orgs.update(editingOrg.id, {
        name: editName,
        config: JSON.parse(editConfig),
      });
      editingOrg = null;
      await loadData();
    } catch (e) {
      alert(e.message);
    }
  }

  async function deleteOrg(id) {
    if (!confirm('Delete this organization? This will also remove it from Redis.')) return;
    try {
      await api.orgs.delete(id);
      await loadData();
    } catch (e) {
      alert(e.message);
    }
  }

  function logout() {
    authStore.logout();
    push('/login');
  }
</script>

<div class="dashboard">
  <header>
    <h1>QuicGuard Dashboard</h1>
    <div class="header-right">
      <span class="user-info">{user ? user.email : ''} ({user ? user.role : ''})</span>
      <button class="btn-logout" on:click={logout}>Logout</button>
    </div>
  </header>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if error}
    <p class="error">{error}</p>
  {:else}
    {#if user && user.role === 'admin'}
      <section class="card">
        <h2>Users</h2>
        <table>
          <thead>
            <tr><th>Email</th><th>Role</th><th>Approved</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {#each users as u (u.id)}
              <tr>
                <td>{u.email}</td>
                <td><span class="badge">{u.role}</span></td>
                <td>{u.approved ? '✓ Yes' : '✗ No'}</td>
                <td class="actions">
                  {#if !u.approved}
                    <button class="btn-approve" on:click={() => approveUser(u.id)}>Approve</button>
                  {/if}
                  <button class="btn-delete" on:click={() => deleteUser(u.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    <section class="card">
      <h2>Organizations</h2>

      <form class="org-form" on:submit|preventDefault={createOrg}>
        <input bind:value={newOrgId} placeholder="Org ID (unique)" required />
        <input bind:value={newOrgName} placeholder="Display Name" required />
        <textarea bind:value={newOrgConfig} placeholder="Config (JSON)" rows="4"></textarea>
        <button type="submit" class="btn-create">Add Organization</button>
      </form>

      {#if editingOrg}
        <div class="edit-panel">
          <h3>Edit: {editingOrg.id}</h3>
          <input bind:value={editName} placeholder="Name" />
          <textarea bind:value={editConfig} rows="10"></textarea>
          <div class="edit-actions">
            <button class="btn-save" on:click={saveEdit}>Save</button>
            <button class="btn-cancel" on:click={() => editingOrg = null}>Cancel</button>
          </div>
        </div>
      {/if}

      <table>
        <thead>
          <tr><th>ID</th><th>Name</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {#each orgs as org (org.id)}
            <tr>
              <td><code>{org.id}</code></td>
              <td>{org.name}</td>
              <td class="actions">
                <button class="btn-edit" on:click={() => startEdit(org)}>Edit</button>
                <button class="btn-delete" on:click={() => deleteOrg(org.id)}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
</div>

<style>
  .dashboard { max-width: 1000px; margin: 0 auto; padding: 2rem; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid #eee; padding-bottom: 1rem; }
  .header-right { display: flex; gap: 1rem; align-items: center; }
  .user-info { color: #666; font-size: 0.9rem; }
  .loading { color: #888; }
  .error { color: #e74c3c; }
  .card { background: #fff; border: 1px solid #eee; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  h2 { margin-top: 0; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #eee; text-align: left; }
  th { background: #f8f9fa; font-weight: 600; }
  code { background: #f0f0f0; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
  .badge { background: #e8f4fd; color: #2980b9; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; }
  .actions { white-space: nowrap; }
  button { padding: 0.35rem 0.7rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85rem; margin-right: 0.3rem; }
  .btn-logout { background: #95a5a6; color: white; }
  .btn-create { background: #27ae60; color: white; padding: 0.6rem 1.2rem; font-size: 1rem; }
  .btn-approve { background: #27ae60; color: white; }
  .btn-edit { background: #3498db; color: white; }
  .btn-save { background: #27ae60; color: white; }
  .btn-cancel { background: #95a5a6; color: white; }
  .btn-delete { background: #e74c3c; color: white; }
  .org-form { display: flex; flex-direction: column; gap: 0.6rem; margin-bottom: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 6px; }
  .org-form input, .org-form textarea { padding: 0.6rem; border: 1px solid #ddd; border-radius: 4px; font-size: 0.95rem; font-family: monospace; }
  .edit-panel { background: #f8f9fa; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
  .edit-panel h3 { margin-top: 0; }
  .edit-panel input, .edit-panel textarea { width: 100%; padding: 0.6rem; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; margin-bottom: 0.5rem; }
  .edit-actions { display: flex; gap: 0.5rem; }
</style>
