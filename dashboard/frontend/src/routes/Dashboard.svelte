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

  // --- Org creation wizard ---
  let showCreateWizard = false;
  let createStep = 1;
  let creating = false;
  let createError = '';

  // Step 1: Basic
  let newId = '';
  let newName = '';
  let upstreamUrl = '';
  let upstreamTimeout = 5000;

  // Step 2: Domains
  let domains = [''];
  let newDomain = '';

  // Step 3: Auth
  let jwtIssuer = '';
  let jwtAudience = '';
  let autoGenerateJwt = true;
  let jwtPublicKey = '';
  let cookieName = 'session_token';
  let redirectUrl = '';
  let idpUrl = '';

  // Step 4: TLS
  let tlsConfigs = [];

  // Step 5: Policies
  let policies = [];

  // --- Org detail view ---
  let selectedOrg = null;
  let orgDetail = null;
  let showPolicyForm = false;
  let showDomainPolicyForm = false;
  let policyDomain = '';

  // Policy form
  let polId = '';
  let polName = '';
  let polEffect = 'Allow';
  let polRules = [{ resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] }];

  // --- Edit org ---
  let editingOrg = false;
  let editStep = 1;
  let saving = false;
  let editError = '';
  let editName = '';
  let editDomains = [''];
  let editUpstreamUrl = '';
  let editUpstreamTimeout = 5000;
  let editJwtIssuer = '';
  let editJwtAudience = '';
  let editAutoGenerateJwt = false;
  let editJwtPublicKey = '';
  let editCookieName = '';
  let editRedirectUrl = '';
  let editIdpUrl = '';
  let editTlsConfigs = [];

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

  // --- User management ---
  async function approveUser(id) {
    await api.admin.approveUser(id);
    await loadData();
  }

  async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    await api.admin.deleteUser(id);
    await loadData();
  }

  // --- Create wizard ---
  function openCreateWizard() {
    showCreateWizard = true;
    createStep = 1;
    createError = '';
    newId = '';
    newName = '';
    upstreamUrl = '';
    upstreamTimeout = 5000;
    domains = [''];
    jwtIssuer = '';
    jwtAudience = '';
    autoGenerateJwt = true;
    jwtPublicKey = '';
    cookieName = 'session_token';
    redirectUrl = '';
    idpUrl = '';
    tlsConfigs = [];
    policies = [];
  }

  function addDomainField() {
    domains = [...domains, ''];
  }

  function removeDomainField(i) {
    domains = domains.filter((_, idx) => idx !== i);
  }

  function initTlsForDomains() {
    tlsConfigs = domains.filter(d => d.trim()).map(d => ({
      domain: d.trim(),
      cert_pem: '',
      key_pem: '',
      auto_generate: true,
    }));
  }

  function addPolicyRule() {
    polRules = [...polRules, { resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] }];
  }

  function removePolicyRule(i) {
    polRules = polRules.filter((_, idx) => idx !== i);
  }

  function addCondition(ruleIdx) {
    polRules[ruleIdx].conditions = [...polRules[ruleIdx].conditions, { claim: 'sub', operator: 'Equals', value: '' }];
    polRules = polRules;
  }

  function removeCondition(ruleIdx, condIdx) {
    polRules[ruleIdx].conditions = polRules[ruleIdx].conditions.filter((_, idx) => idx !== condIdx);
    polRules = polRules;
  }

  function savePolicy() {
    policies = [...policies, {
      policy_id: polId || `pol-${Date.now()}`,
      name: polName,
      effect: polEffect,
      rules: polRules.map(r => ({
        resource_type: r.resourceType,
        resource_value: r.resourceValue,
        methods: r.methods,
        conditions: r.conditions,
      })),
    }];
    polId = '';
    polName = '';
    polEffect = 'Allow';
    polRules = [{ resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] }];
    showPolicyForm = false;
  }

  function removePolicy(idx) {
    policies = policies.filter((_, i) => i !== idx);
  }

  async function submitCreateOrg() {
    creating = true;
    createError = '';
    try {
      const validDomains = domains.filter(d => d.trim());
      const tls = tlsConfigs.map(t => ({
        domain: t.domain,
        cert_pem: t.auto_generate ? null : t.cert_pem || null,
        key_pem: t.auto_generate ? null : t.key_pem || null,
        auto_generate: t.auto_generate,
      }));

      await api.orgs.create({
        id: newId.trim(),
        name: newName.trim(),
        domains: validDomains,
        upstream_base_url: upstreamUrl.trim(),
        upstream_timeout_ms: upstreamTimeout,
        jwt_issuer: jwtIssuer.trim(),
        jwt_audience: jwtAudience.trim(),
        jwt_public_key: autoGenerateJwt ? null : jwtPublicKey || null,
        auto_generate_jwt_keys: autoGenerateJwt,
        cookie_name: cookieName || null,
        redirect_url: redirectUrl || null,
        idp_url: idpUrl || null,
        tls_configs: tls,
      });

      // Add policies to the created org
      const orgId = newId.trim();
      for (const pol of policies) {
        await api.orgs.addPolicy(orgId, pol);
      }

      showCreateWizard = false;
      await loadData();
    } catch (e) {
      createError = e.message || 'Failed to create organization';
    } finally {
      creating = false;
    }
  }

  // --- Org detail ---
  async function viewOrg(org) {
    selectedOrg = org;
    try {
      const res = await api.orgs.get(org.id);
      orgDetail = res;
    } catch (e) {
      error = e.message;
    }
  }

  function closeDetail() {
    selectedOrg = null;
    orgDetail = null;
    showPolicyForm = false;
    showDomainPolicyForm = false;
    editingOrg = false;
  }

  // --- Edit org ---
  function enterEditMode() {
    if (!orgDetail) return;
    editingOrg = true;
    editStep = 1;
    editError = '';

    editName = orgDetail.name || '';
    editDomains = [...(orgDetail.config.domains || [])];
    if (editDomains.length === 0) editDomains = [''];
    editUpstreamUrl = orgDetail.config.upstream?.base_url || '';
    editUpstreamTimeout = orgDetail.config.upstream?.timeout_ms || 5000;
    editJwtIssuer = orgDetail.config.auth?.jwt_issuer || '';
    editJwtAudience = orgDetail.config.auth?.jwt_audience || '';
    editAutoGenerateJwt = false;
    editJwtPublicKey = orgDetail.config.auth?.jwt_public_key || '';
    editCookieName = orgDetail.config.auth?.cookie_name || '';
    editRedirectUrl = orgDetail.config.auth?.redirect_url || '';
    editIdpUrl = orgDetail.config.auth?.idp_url || '';

    editTlsConfigs = Object.entries(orgDetail.config.tls || {}).map(([domain, tls]) => ({
      domain,
      cert_pem: tls.cert_pem || '',
      key_pem: tls.key_pem || '',
      auto_generate: false,
    }));
  }

  function cancelEdit() {
    editingOrg = false;
    editError = '';
  }

  function addEditDomainField() {
    editDomains = [...editDomains, ''];
  }

  function removeEditDomainField(i) {
    editDomains = editDomains.filter((_, idx) => idx !== i);
  }

  async function submitEditOrg() {
    if (!selectedOrg) return;
    saving = true;
    editError = '';
    try {
      const validDomains = editDomains.filter(d => d.trim());
      const tls = editTlsConfigs.map(t => ({
        domain: t.domain,
        cert_pem: t.auto_generate ? null : (t.cert_pem || null),
        key_pem: t.auto_generate ? null : (t.key_pem || null),
        auto_generate: t.auto_generate,
      }));

      await api.orgs.updateRaw(selectedOrg.id, {
        name: editName.trim() || undefined,
        domains: validDomains.length > 0 ? validDomains : undefined,
        upstream_base_url: editUpstreamUrl.trim() || undefined,
        upstream_timeout_ms: editUpstreamTimeout || undefined,
        jwt_issuer: editJwtIssuer.trim() || undefined,
        jwt_audience: editJwtAudience.trim() || undefined,
        jwt_public_key: editAutoGenerateJwt ? null : (editJwtPublicKey || undefined),
        auto_generate_jwt_keys: editAutoGenerateJwt,
        cookie_name: editCookieName || undefined,
        redirect_url: editRedirectUrl || undefined,
        idp_url: editIdpUrl || undefined,
        tls_configs: tls.length > 0 ? tls : undefined,
      });

      const res = await api.orgs.get(selectedOrg.id);
      orgDetail = res;
      editingOrg = false;
    } catch (e) {
      editError = e.message || 'Failed to update organization';
    } finally {
      saving = false;
    }
  }

  async function deleteOrg(id) {
    if (!confirm('Delete this organization? This will also remove it from Redis.')) return;
    await api.orgs.delete(id);
    selectedOrg = null;
    orgDetail = null;
    await loadData();
  }

  async function removeOrgPolicy(policyId) {
    if (!selectedOrg) return;
    await api.orgs.removePolicy(selectedOrg.id, policyId);
    const res = await api.orgs.get(selectedOrg.id);
    orgDetail = res;
  }

  async function addOrgPolicy() {
    if (!selectedOrg) return;
    await api.orgs.addPolicy(selectedOrg.id, {
      policy_id: polId || `pol-${Date.now()}`,
      name: polName,
      effect: polEffect,
      rules: polRules.map(r => ({
        resource_type: r.resourceType,
        resource_value: r.resourceValue,
        methods: r.methods,
        conditions: r.conditions,
      })),
    });
    polId = '';
    polName = '';
    polEffect = 'Allow';
    polRules = [{ resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] }];
    showPolicyForm = false;
    const res = await api.orgs.get(selectedOrg.id);
    orgDetail = res;
  }

  async function addOrgDomainPolicy() {
    if (!selectedOrg || !policyDomain) return;
    await api.orgs.addDomainPolicy(selectedOrg.id, {
      domain: policyDomain,
      policy_id: polId || `dpol-${Date.now()}`,
      name: polName,
      effect: polEffect,
      rules: polRules.map(r => ({
        resource_type: r.resourceType,
        resource_value: r.resourceValue,
        methods: r.methods,
        conditions: r.conditions,
      })),
    });
    polId = '';
    polName = '';
    polEffect = 'Allow';
    policyDomain = '';
    polRules = [{ resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] }];
    showDomainPolicyForm = false;
    const res = await api.orgs.get(selectedOrg.id);
    orgDetail = res;
  }

  async function removeOrgDomainPolicy(domain, policyId) {
    if (!selectedOrg) return;
    await api.orgs.removeDomainPolicy(selectedOrg.id, domain, policyId);
    const res = await api.orgs.get(selectedOrg.id);
    orgDetail = res;
  }

  function logout() {
    authStore.logout();
    push('/login');
  }

  function toggleMethod(rule, method) {
    if (rule.methods.includes(method)) {
      rule.methods = rule.methods.filter(m => m !== method);
    } else {
      rule.methods = [...rule.methods, method];
    }
    polRules = polRules;
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

    <!-- Admin: Users section -->
    {#if user && user.role === 'admin'}
      <section class="card">
        <h2>Users</h2>
        <table>
          <thead><tr><th>Email</th><th>Role</th><th>Approved</th><th>Actions</th></tr></thead>
          <tbody>
            {#each users as u (u.id)}
              <tr>
                <td>{u.email}</td>
                <td><span class="badge">{u.role}</span></td>
                <td>{u.approved ? 'Yes' : 'No'}</td>
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

    <!-- Org detail view -->
    {#if selectedOrg && orgDetail}
      <section class="card">
        <div class="detail-header">
          <h2>{orgDetail.name} <code>{orgDetail.id}</code></h2>
          <div>
            {#if !editingOrg}
              <button class="btn-edit" on:click={enterEditMode}>Edit</button>
            {/if}
            <button class="btn-cancel" on:click={closeDetail}>Back to list</button>
            <button class="btn-delete" on:click={() => deleteOrg(orgDetail.id)}>Delete Org</button>
          </div>
        </div>

        {#if !editingOrg}
        <!-- Domains -->
        <div class="detail-section">
          <h3>Domains</h3>
          <div class="tag-list">
            {#each (orgDetail.config.domains || []) as d}
              <span class="tag">{d}</span>
            {:else}
              <span class="muted">No domains configured</span>
            {/each}
          </div>
        </div>

        <!-- Upstream -->
        <div class="detail-section">
          <h3>Upstream</h3>
          <p>URL: <code>{orgDetail.config.upstream?.base_url || '-'}</code></p>
          <p>Timeout: {orgDetail.config.upstream?.timeout_ms || '-'}ms</p>
        </div>

        <!-- Auth -->
        <div class="detail-section">
          <h3>Auth</h3>
          <p>Issuer: <code>{orgDetail.config.auth?.jwt_issuer || '-'}</code></p>
          <p>Audience: <code>{orgDetail.config.auth?.jwt_audience || '-'}</code></p>
          <p>IDP URL: <code>{orgDetail.config.auth?.idp_url || '-'}</code></p>
        </div>

        <!-- TLS -->
        <div class="detail-section">
          <h3>TLS Certificates</h3>
          {#each Object.entries(orgDetail.config.tls || {}) as [domain, tls]}
            <div class="tls-entry">
              <span class="tag">{domain}</span>
              <span class="muted">{tls.cert_pem ? 'Certificate provided' : 'No certificate'}</span>
            </div>
          {:else}
            <span class="muted">No TLS configured</span>
          {/each}
        </div>
        {/if}

        <!-- Edit wizard -->
        {#if editingOrg}
          <div class="edit-wizard card">
            <h3>Edit Organization</h3>
            {#if editError}
              <div class="error">{editError}</div>
            {/if}

            <div class="steps">
              {#each ['Basic Info', 'Domains', 'Auth', 'TLS'] as step, i}
                <span class="step" class:active={editStep === i + 1} class:done={editStep > i + 1}>
                  {i + 1}. {step}
                </span>
              {/each}
            </div>

            {#if editStep === 1}
              <div class="step-content">
                <label>Name <input bind:value={editName} placeholder="Organization name" /></label>
                <label>Upstream URL <input bind:value={editUpstreamUrl} placeholder="http://localhost:8080" /></label>
                <label>Upstream Timeout (ms) <input type="number" bind:value={editUpstreamTimeout} /></label>
              </div>
            {:else if editStep === 2}
              <div class="step-content">
                {#each editDomains as _, i}
                  <div class="domain-row">
                    <input bind:value={editDomains[i]} placeholder="app.example.com" />
                    {#if editDomains.length > 1}
                      <button class="btn-delete-sm" on:click={() => removeEditDomainField(i)}>x</button>
                    {/if}
                  </div>
                {/each}
                <button class="btn-add-sm" on:click={addEditDomainField}>+ Add Domain</button>
              </div>
            {:else if editStep === 3}
              <div class="step-content">
                <label>JWT Issuer <input bind:value={editJwtIssuer} placeholder="https://auth.example.com" /></label>
                <label>JWT Audience <input bind:value={editJwtAudience} placeholder="quicguard-proxy" /></label>
                <label class="check-label">
                  <input type="checkbox" bind:checked={editAutoGenerateJwt} /> Regenerate JWT key pair
                </label>
                {#if !editAutoGenerateJwt}
                  <label>JWT Public Key (PEM) <textarea bind:value={editJwtPublicKey} rows="4"></textarea></label>
                {/if}
                <label>Cookie Name <input bind:value={editCookieName} /></label>
                <label>Redirect URL <input bind:value={editRedirectUrl} /></label>
                <label>IDP URL <input bind:value={editIdpUrl} /></label>
              </div>
            {:else if editStep === 4}
              <div class="step-content">
                {#if editTlsConfigs.length === 0}
                  <p class="muted">No TLS configurations.</p>
                {/if}
                {#each editTlsConfigs as tls, i}
                  <div class="tls-card">
                    <h4>{tls.domain}</h4>
                    <label class="check-label">
                      <input type="checkbox" bind:checked={tls.auto_generate} /> Regenerate certificate
                    </label>
                    {#if !tls.auto_generate}
                      <label>Certificate PEM <textarea bind:value={tls.cert_pem} rows="3"></textarea></label>
                      <label>Private Key PEM <textarea bind:value={tls.key_pem} rows="3"></textarea></label>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}

            <div class="wizard-nav">
              {#if editStep > 1}
                <button class="btn-cancel" on:click={() => editStep--}>Back</button>
              {/if}
              {#if editStep < 4}
                <button class="btn-save" on:click={() => editStep++}>Next</button>
              {:else}
                <button class="btn-save" on:click={submitEditOrg} disabled={saving}>
                  {saving ? 'Saving...' : 'Save Changes'}
                </button>
              {/if}
              <button class="btn-cancel" on:click={cancelEdit}>Cancel</button>
            </div>
          </div>
        {/if}

        <!-- Policies -->
        <div class="detail-section">
          <h3>Policies</h3>
          {#each (orgDetail.config.policies || []) as pol}
            <div class="policy-card">
              <div class="policy-header">
                <span class="policy-name">{pol.name}</span>
                <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                <button class="btn-delete-sm" on:click={() => removeOrgPolicy(pol.id)}>Remove</button>
              </div>
              {#each pol.rules as rule}
                <div class="policy-rule">
                  <code>{JSON.stringify(rule.resource)}</code>
                  <span>Methods: {rule.methods.join(', ')}</span>
                  {#if rule.conditions?.length}
                    <span>Conditions: {rule.conditions.length}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <span class="muted">No policies</span>
          {/each}

          {#if !showPolicyForm}
            <button class="btn-create" on:click={() => { showPolicyForm = true; showDomainPolicyForm = false; }}>Add Policy</button>
          {/if}
        </div>

        <!-- Domain Policies -->
        <div class="detail-section">
          <h3>Domain-Specific Policies</h3>
          {#each Object.entries(orgDetail.config.domain_policies || {}) as [domain, dpolList]}
            <div class="domain-policy-group">
              <h4><code>{domain}</code></h4>
              {#each dpolList as pol}
                <div class="policy-card">
                  <div class="policy-header">
                    <span class="policy-name">{pol.name}</span>
                    <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                    <button class="btn-delete-sm" on:click={() => removeOrgDomainPolicy(domain, pol.id)}>Remove</button>
                  </div>
                  {#each pol.rules as rule}
                    <div class="policy-rule">
                      <code>{JSON.stringify(rule.resource)}</code>
                      <span>Methods: {rule.methods.join(', ')}</span>
                    </div>
                  {/each}
                </div>
              {/each}
            </div>
          {:else}
            <span class="muted">No domain-specific policies</span>
          {/each}

          {#if !showDomainPolicyForm}
            <button class="btn-create" on:click={() => { showDomainPolicyForm = true; showPolicyForm = false; }}>Add Domain Policy</button>
          {/if}
        </div>

        <!-- Policy form (shared for org and domain policies) -->
        {#if showPolicyForm || showDomainPolicyForm}
          <div class="policy-form card">
            <h3>{showDomainPolicyForm ? 'Add Domain Policy' : 'Add Policy'}</h3>
            {#if showDomainPolicyForm}
              <label>Domain
                <select bind:value={policyDomain}>
                  <option value="">Select domain...</option>
                  {#each (orgDetail.config.domains || []) as d}
                    <option value={d}>{d}</option>
                  {/each}
                </select>
              </label>
            {/if}
            <label>Policy ID <input bind:value={polId} placeholder="auto-generated if empty" /></label>
            <label>Name <input bind:value={polName} placeholder="e.g. Allow public read" required /></label>
            <label>Effect
              <select bind:value={polEffect}>
                <option value="Allow">Allow</option>
                <option value="Deny">Deny</option>
              </select>
            </label>

            <h4>Rules</h4>
            {#each polRules as rule, ri}
              <div class="rule-card">
                <label>Resource Type
                  <select bind:value={rule.resourceType}>
                    <option value="prefix">Prefix</option>
                    <option value="exact">Exact</option>
                    <option value="glob">Glob</option>
                  </select>
                </label>
                <label>Resource Value <input bind:value={rule.resourceValue} placeholder="/api/v1/" /></label>
                <label>Methods
                  <div class="method-checks">
                    {#each ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as m}
                      <label class="check-label">
                        <input type="checkbox" checked={rule.methods.includes(m)} on:change={() => toggleMethod(rule, m)} /> {m}
                      </label>
                    {/each}
                  </div>
                </label>

                <div class="conditions">
                  <span>Conditions:</span>
                  {#each rule.conditions as cond, ci}
                    <div class="condition-row">
                      <input bind:value={cond.claim} placeholder="claim" />
                      <select bind:value={cond.operator}>
                        <option value="Equals">Equals</option>
                        <option value="NotEquals">NotEquals</option>
                        <option value="Contains">Contains</option>
                        <option value="StartsWith">StartsWith</option>
                        <option value="In">In</option>
                        <option value="NotIn">NotIn</option>
                      </select>
                      <input bind:value={cond.value} placeholder="value" />
                      <button class="btn-delete-sm" on:click={() => removeCondition(ri, ci)}>x</button>
                    </div>
                  {/each}
                  <button class="btn-add-sm" on:click={() => addCondition(ri)}>+ Condition</button>
                </div>

                {#if polRules.length > 1}
                  <button class="btn-delete-sm" on:click={() => removePolicyRule(ri)}>Remove rule</button>
                {/if}
              </div>
            {/each}
            <button class="btn-add-sm" on:click={addPolicyRule}>+ Add Rule</button>

            <div class="form-actions">
              <button class="btn-save" on:click={showDomainPolicyForm ? addOrgDomainPolicy : addOrgPolicy}>
                {showDomainPolicyForm ? 'Add Domain Policy' : 'Add Policy'}
              </button>
              <button class="btn-cancel" on:click={() => { showPolicyForm = false; showDomainPolicyForm = false; }}>Cancel</button>
            </div>
          </div>
        {/if}
      </section>

    <!-- Create wizard -->
    {:else if showCreateWizard}
      <section class="card">
        <h2>Create Organization</h2>
        {#if createError}
          <div class="error">{createError}</div>
        {/if}

        <div class="steps">
          {#each ['Basic Info', 'Domains', 'Auth', 'TLS', 'Policies'] as step, i}
            <span class="step" class:active={createStep === i + 1} class:done={createStep > i + 1}>
              {i + 1}. {step}
            </span>
          {/each}
        </div>

        <!-- Step 1: Basic Info -->
        {#if createStep === 1}
          <div class="step-content">
            <label>Org ID <input bind:value={newId} placeholder="my-org" required /></label>
            <label>Name <input bind:value={newName} placeholder="My Organization" required /></label>
            <label>Upstream URL <input bind:value={upstreamUrl} placeholder="http://localhost:8080" required /></label>
            <label>Upstream Timeout (ms) <input type="number" bind:value={upstreamTimeout} /></label>
          </div>

        <!-- Step 2: Domains -->
        {:else if createStep === 2}
          <div class="step-content">
            <p class="muted">Add domains this organization serves. TLS certificates can be auto-generated or provided manually.</p>
            {#each domains as _, i}
              <div class="domain-row">
                <input bind:value={domains[i]} placeholder="app.example.com" />
                {#if domains.length > 1}
                  <button class="btn-delete-sm" on:click={() => removeDomainField(i)}>x</button>
                {/if}
              </div>
            {/each}
            <button class="btn-add-sm" on:click={addDomainField}>+ Add Domain</button>
          </div>

        <!-- Step 3: Auth -->
        {:else if createStep === 3}
          <div class="step-content">
            <label>JWT Issuer <input bind:value={jwtIssuer} placeholder="https://auth.example.com" /></label>
            <label>JWT Audience <input bind:value={jwtAudience} placeholder="quicguard-proxy" /></label>
            <label class="check-label">
              <input type="checkbox" bind:checked={autoGenerateJwt} /> Auto-generate JWT key pair
            </label>
            {#if !autoGenerateJwt}
              <label>JWT Public Key (PEM) <textarea bind:value={jwtPublicKey} rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea></label>
            {/if}
            <label>Cookie Name <input bind:value={cookieName} placeholder="session_token" /></label>
            <label>Redirect URL <input bind:value={redirectUrl} placeholder="https://auth.example.com/login" /></label>
            <label>IDP URL <input bind:value={idpUrl} placeholder="https://auth.example.com/idp" /></label>
          </div>

        <!-- Step 4: TLS -->
        {:else if createStep === 4}
          <div class="step-content">
            {#if tlsConfigs.length === 0}
              <p class="muted">No domains to configure TLS for. Go back to add domains.</p>
            {/if}
            {#each tlsConfigs as tls, i}
              <div class="tls-card">
                <h4>{tls.domain}</h4>
                <label class="check-label">
                  <input type="checkbox" bind:checked={tls.auto_generate} /> Auto-generate self-signed certificate
                </label>
                {#if !tls.auto_generate}
                  <label>Certificate PEM <textarea bind:value={tls.cert_pem} rows="4" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
                  <label>Private Key PEM <textarea bind:value={tls.key_pem} rows="4" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>
                {/if}
              </div>
            {/each}
          </div>

        <!-- Step 5: Policies -->
        {:else if createStep === 5}
          <div class="step-content">
            <p class="muted">Define access policies. These are org-level policies applied to all domains. You can add domain-specific policies after creation.</p>
            {#each policies as pol, i}
              <div class="policy-card">
                <div class="policy-header">
                  <span class="policy-name">{pol.name}</span>
                  <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                  <button class="btn-delete-sm" on:click={() => removePolicy(i)}>Remove</button>
                </div>
                {#each pol.rules as rule}
                  <div class="policy-rule">
                    <code>{rule.resource_type}: {rule.resource_value}</code>
                    <span>{rule.methods.join(', ')}</span>
                  </div>
                {/each}
              </div>
            {/each}

            {#if !showPolicyForm}
              <button class="btn-create" on:click={() => showPolicyForm = true}>+ Add Policy</button>
            {/if}

            {#if showPolicyForm}
              <div class="policy-form-inner">
                <label>Policy ID <input bind:value={polId} placeholder="auto-generated if empty" /></label>
                <label>Name <input bind:value={polName} placeholder="e.g. Allow public read" required /></label>
                <label>Effect
                  <select bind:value={polEffect}>
                    <option value="Allow">Allow</option>
                    <option value="Deny">Deny</option>
                  </select>
                </label>

                {#each polRules as rule, ri}
                  <div class="rule-card">
                    <label>Resource Type
                      <select bind:value={rule.resourceType}>
                        <option value="prefix">Prefix</option>
                        <option value="exact">Exact</option>
                        <option value="glob">Glob</option>
                      </select>
                    </label>
                    <label>Resource Value <input bind:value={rule.resourceValue} placeholder="/api/v1/" /></label>
                    <label>Methods
                      <div class="method-checks">
                        {#each ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as m}
                          <label class="check-label">
                            <input type="checkbox" checked={rule.methods.includes(m)} on:change={() => toggleMethod(rule, m)} /> {m}
                          </label>
                        {/each}
                      </div>
                    </label>

                    {#each rule.conditions as cond, ci}
                      <div class="condition-row">
                        <input bind:value={cond.claim} placeholder="claim" />
                        <select bind:value={cond.operator}>
                          <option value="Equals">Equals</option>
                          <option value="NotEquals">NotEquals</option>
                          <option value="Contains">Contains</option>
                          <option value="StartsWith">StartsWith</option>
                        </select>
                        <input bind:value={cond.value} placeholder="value" />
                        <button class="btn-delete-sm" on:click={() => removeCondition(ri, ci)}>x</button>
                      </div>
                    {/each}
                    <button class="btn-add-sm" on:click={() => addCondition(ri)}>+ Condition</button>

                    {#if polRules.length > 1}
                      <button class="btn-delete-sm" on:click={() => removePolicyRule(ri)}>Remove rule</button>
                    {/if}
                  </div>
                {/each}
                <button class="btn-add-sm" on:click={addPolicyRule}>+ Add Rule</button>

                <div class="form-actions">
                  <button class="btn-save" on:click={savePolicy}>Save Policy</button>
                  <button class="btn-cancel" on:click={() => showPolicyForm = false}>Cancel</button>
                </div>
              </div>
            {/if}
          </div>
        {/if}

        <!-- Navigation -->
        <div class="wizard-nav">
          {#if createStep > 1}
            <button class="btn-cancel" on:click={() => createStep--}>Back</button>
          {/if}
          {#if createStep === 2}
            <button class="btn-save" on:click={() => { initTlsForDomains(); createStep++; }}>Next</button>
          {:else if createStep < 5}
            <button class="btn-save" on:click={() => createStep++}>Next</button>
          {:else}
            <button class="btn-create" on:click={submitCreateOrg} disabled={creating}>
              {creating ? 'Creating...' : 'Create Organization'}
            </button>
          {/if}
          <button class="btn-cancel" on:click={() => showCreateWizard = false}>Cancel</button>
        </div>
      </section>

    <!-- Org list -->
    {:else}
      <section class="card">
        <div class="section-header">
          <h2>Organizations</h2>
          <button class="btn-create" on:click={openCreateWizard}>+ New Organization</button>
        </div>

        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Domains</th><th>Actions</th></tr></thead>
          <tbody>
            {#each orgs as org (org.id)}
              <tr>
                <td><code>{org.id}</code></td>
                <td>{org.name}</td>
                <td>
                  {#each (org.config?.domains || []).slice(0, 3) as d}
                    <span class="tag">{d}</span>
                  {/each}
                  {#if (org.config?.domains || []).length > 3}
                    <span class="muted">+{(org.config?.domains || []).length - 3} more</span>
                  {/if}
                </td>
                <td class="actions">
                  <button class="btn-edit" on:click={() => viewOrg(org)}>View</button>
                  <button class="btn-delete" on:click={() => deleteOrg(org.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}
  {/if}
</div>

<style>
  .dashboard { max-width: 1100px; margin: 0 auto; padding: 2rem; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid #eee; padding-bottom: 1rem; }
  .header-right { display: flex; gap: 1rem; align-items: center; }
  .user-info { color: #666; font-size: 0.9rem; }
  .loading { color: #888; }
  .error { color: #e74c3c; margin-bottom: 1rem; padding: 0.75rem; background: #fdecea; border-radius: 4px; }
  .card { background: #fff; border: 1px solid #eee; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  h2 { margin-top: 0; }
  h3 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  h4 { margin: 0.5rem 0 0.3rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #eee; text-align: left; }
  th { background: #f8f9fa; font-weight: 600; }
  code { background: #f0f0f0; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
  .badge { background: #e8f4fd; color: #2980b9; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; }
  .badge-allow { background: #eafaf1; color: #27ae60; }
  .badge-deny { background: #fdecea; color: #e74c3c; }
  .tag { background: #f0f0f0; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.8rem; display: inline-block; margin: 0.1rem; }
  .muted { color: #999; font-size: 0.9rem; }
  .tag-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .actions { white-space: nowrap; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .section-header h2 { margin: 0; }

  button { padding: 0.35rem 0.7rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85rem; margin-right: 0.3rem; }
  .btn-logout { background: #95a5a6; color: white; }
  .btn-create { background: #27ae60; color: white; padding: 0.5rem 1rem; font-size: 0.95rem; }
  .btn-approve { background: #27ae60; color: white; }
  .btn-edit { background: #3498db; color: white; }
  .btn-save { background: #2980b9; color: white; }
  .btn-cancel { background: #95a5a6; color: white; }
  .btn-delete { background: #e74c3c; color: white; }
  .btn-delete-sm { background: none; color: #e74c3c; padding: 0.2rem 0.4rem; font-size: 0.8rem; }
  .btn-add-sm { background: none; color: #3498db; padding: 0.2rem 0.4rem; font-size: 0.8rem; border: 1px dashed #3498db; margin-top: 0.3rem; }

  /* Detail view */
  .detail-header { display: flex; justify-content: space-between; align-items: center; }
  .detail-header h2 { margin: 0; }
  .detail-section { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #eee; }
  .tls-entry { display: flex; align-items: center; gap: 0.5rem; margin: 0.3rem 0; }
  .domain-policy-group { margin-bottom: 1rem; }

  /* Policy cards */
  .policy-card { background: #f8f9fa; border: 1px solid #eee; border-radius: 6px; padding: 0.8rem; margin: 0.5rem 0; }
  .policy-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; }
  .policy-name { font-weight: 600; }
  .policy-rule { font-size: 0.85rem; color: #555; margin: 0.2rem 0; display: flex; gap: 1rem; align-items: center; }

  /* Forms */
  label { display: block; margin: 0.8rem 0; font-weight: 500; }
  input, select, textarea { display: block; width: 100%; padding: 0.6rem; border: 1px solid #ddd; border-radius: 4px; font-size: 0.95rem; margin-top: 0.3rem; font-family: inherit; }
  textarea { font-family: monospace; font-size: 0.85rem; }
  .check-label { display: inline-flex !important; align-items: center; gap: 0.4rem; font-weight: 400; cursor: pointer; }
  .check-label input { width: auto; }
  .method-checks { display: flex; gap: 0.8rem; margin-top: 0.3rem; }
  .domain-row { display: flex; gap: 0.5rem; align-items: center; margin: 0.4rem 0; }
  .domain-row input { flex: 1; }
  .condition-row { display: flex; gap: 0.4rem; align-items: center; margin: 0.3rem 0; }
  .condition-row input, .condition-row select { width: auto; flex: 1; }
  .form-actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
  .policy-form { margin-top: 1rem; }
  .policy-form-inner { background: #f0f4f8; padding: 1rem; border-radius: 6px; margin-top: 0.5rem; }
  .rule-card { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 0.8rem; margin: 0.5rem 0; }
  .conditions { margin-top: 0.5rem; }
  .conditions > span { font-size: 0.85rem; color: #666; }

  /* Wizard */
  .steps { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid #eee; }
  .step { padding: 0.4rem 0.8rem; border-radius: 20px; background: #f0f0f0; color: #888; font-size: 0.85rem; }
  .step.active { background: #3498db; color: white; }
  .step.done { background: #27ae60; color: white; }
  .step-content { min-height: 200px; }
  .wizard-nav { display: flex; gap: 0.5rem; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #eee; }
  .tls-card { background: #f8f9fa; border: 1px solid #eee; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }
  .edit-wizard { margin-top: 1rem; }
</style>
