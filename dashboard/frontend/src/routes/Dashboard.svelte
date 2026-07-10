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

  // Step 2: Domains (each has upstream, TLS, policies)
  let createDomains = [makeDomainEntry()];

  // Step 3: Apps
  let createApps = [makeAppEntry()];

  // Step 4: User Groups
  let createUserGroups = [makeUserGroupEntry()];
  let createAppUserGroups = {};

  // Step 5: Auth
  let jwtIssuer = '';
  let jwtAudience = '';
  let autoGenerateJwt = true;
  let jwtPublicKey = '';
  let cookieName = 'session_token';
  let redirectUrl = '';
  let idpUrl = '';
  let reqParamName = 'req';
  let tokenParamName = 'token';

  // --- Org detail view ---
  let selectedOrg = null;
  let orgDetail = null;
  let expandedDomain = '';
  let showPolicyForm = false;
  let policyDomain = '';

  // Policy form fields
  let polId = '';
  let polName = '';
  let polEffect = 'Allow';
  let polRules = [makeRule()];

  // --- Edit org ---
  let editingOrg = false;
  let editStep = 1;
  let saving = false;
  let editError = '';
  let editName = '';
  let editDomains = [makeDomainEntry()];
  let editApps = [makeAppEntry()];
  let editUserGroups = [makeUserGroupEntry()];
  let editAppUserGroups = {};
  let editJwtIssuer = '';
  let editJwtAudience = '';
  let editAutoGenerateJwt = false;
  let editJwtPublicKey = '';
  let editCookieName = '';
  let editRedirectUrl = '';
  let editIdpUrl = '';
  let editReqParamName = 'req';
  let editTokenParamName = 'token';

  // --- Per-domain policy form (in create/edit wizards) ---
  let policyTarget = ''; // domain key within createDomains or editDomains, or 'app:appId'
  let showWizardPolicyForm = false;
  let editingPolicyIndex = -1; // -1 = adding new, >= 0 = editing existing

  function makeRule() {
    return { resourceType: 'prefix', resourceValue: '/', methods: ['GET'], conditions: [] };
  }

  function makeDomainEntry() {
    return {
      name: '',
      upstreamUrl: '',
      upstreamTimeout: 5000,
      autoGenerateTls: true,
      tlsCertPem: '',
      tlsKeyPem: '',
      policies: [],
    };
  }

  function makeAppEntry() {
    return {
      id: `app-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      domains: [],
      policies: [],
    };
  }

  function makeUserGroupEntry() {
    return {
      id: '',
      emails: [],
      emailPatterns: [],
    };
  }

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

  // --- Create wizard helpers ---
  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  function get_resource_type(resource) {
    if (!resource) return 'prefix';
    if (resource.Exact !== undefined) return 'exact';
    if (resource.Prefix !== undefined) return 'prefix';
    if (resource.Glob !== undefined) return 'glob';
    return 'prefix';
  }

  function get_resource_value(resource) {
    if (!resource) return '/';
    if (resource.Exact !== undefined) return resource.Exact;
    if (resource.Prefix !== undefined) return resource.Prefix;
    if (resource.Glob !== undefined) return resource.Glob;
    return '/';
  }

  function openCreateWizard() {
    showCreateWizard = true;
    createStep = 1;
    createError = '';
    newId = generateUUID();
    newName = '';
    createDomains = [makeDomainEntry()];
    createApps = [makeAppEntry()];
    createUserGroups = [makeUserGroupEntry()];
    createAppUserGroups = {};
    jwtIssuer = '';
    jwtAudience = '';
    autoGenerateJwt = true;
    jwtPublicKey = '';
    cookieName = 'session_token';
    redirectUrl = '';
    idpUrl = '';
    reqParamName = 'req';
    tokenParamName = 'token';
  }

  function addCreateDomain() {
    createDomains = [...createDomains, makeDomainEntry()];
  }

  function removeCreateDomain(i) {
    createDomains = createDomains.filter((_, idx) => idx !== i);
  }

  function addCreateApp() {
    createApps = [...createApps, makeAppEntry()];
  }

  function removeCreateApp(i) {
    createApps = createApps.filter((_, idx) => idx !== i);
  }

  function toggleAppDomain(app, domain) {
    if (app.domains.includes(domain)) {
      app.domains = app.domains.filter(d => d !== domain);
    } else {
      app.domains = [...app.domains, domain];
    }
  }

  // --- User Groups (create wizard) ---
  function addUserGroup() {
    createUserGroups = [...createUserGroups, makeUserGroupEntry()];
  }

  function removeUserGroup(i) {
    const groupId = createUserGroups[i].id;
    for (const appId in createAppUserGroups) {
      createAppUserGroups[appId] = createAppUserGroups[appId].filter(g => g !== groupId);
    }
    createUserGroups = createUserGroups.filter((_, idx) => idx !== i);
  }

  function addEmail(groupIdx) {
    createUserGroups[groupIdx].emails = [...createUserGroups[groupIdx].emails, ''];
  }

  function removeEmail(groupIdx, emailIdx) {
    createUserGroups[groupIdx].emails = createUserGroups[groupIdx].emails.filter((_, i) => i !== emailIdx);
    createUserGroups = createUserGroups;
  }

  function addEmailPattern(groupIdx) {
    createUserGroups[groupIdx].emailPatterns = [...createUserGroups[groupIdx].emailPatterns, ''];
  }

  function removeEmailPattern(groupIdx, patternIdx) {
    createUserGroups[groupIdx].emailPatterns = createUserGroups[groupIdx].emailPatterns.filter((_, i) => i !== patternIdx);
    createUserGroups = createUserGroups;
  }

  function isGroupAssignedToApp(groupId, appId) {
    return createAppUserGroups[appId]?.includes(groupId) || false;
  }

  function toggleGroupAppAssignment(groupId, appId) {
    if (!createAppUserGroups[appId]) {
      createAppUserGroups[appId] = [];
    }
    if (createAppUserGroups[appId].includes(groupId)) {
      createAppUserGroups[appId] = createAppUserGroups[appId].filter(g => g !== groupId);
    } else {
      createAppUserGroups[appId].push(groupId);
    }
  }

  // --- User Groups (edit wizard) ---
  function addEditUserGroup() {
    editUserGroups = [...editUserGroups, makeUserGroupEntry()];
  }

  function removeEditUserGroup(i) {
    const groupId = editUserGroups[i].id;
    for (const appId in editAppUserGroups) {
      editAppUserGroups[appId] = editAppUserGroups[appId].filter(g => g !== groupId);
    }
    editUserGroups = editUserGroups.filter((_, idx) => idx !== i);
  }

  function addEditEmail(groupIdx) {
    editUserGroups[groupIdx].emails = [...editUserGroups[groupIdx].emails, ''];
  }

  function removeEditEmail(groupIdx, emailIdx) {
    editUserGroups[groupIdx].emails = editUserGroups[groupIdx].emails.filter((_, i) => i !== emailIdx);
    editUserGroups = editUserGroups;
  }

  function addEditEmailPattern(groupIdx) {
    editUserGroups[groupIdx].emailPatterns = [...editUserGroups[groupIdx].emailPatterns, ''];
  }

  function removeEditEmailPattern(groupIdx, patternIdx) {
    editUserGroups[groupIdx].emailPatterns = editUserGroups[groupIdx].emailPatterns.filter((_, i) => i !== patternIdx);
    editUserGroups = editUserGroups;
  }

  function isEditGroupAssignedToApp(groupId, appId) {
    return editAppUserGroups[appId]?.includes(groupId) || false;
  }

  function toggleEditGroupAppAssignment(groupId, appId) {
    if (!editAppUserGroups[appId]) {
      editAppUserGroups[appId] = [];
    }
    if (editAppUserGroups[appId].includes(groupId)) {
      editAppUserGroups[appId] = editAppUserGroups[appId].filter(g => g !== groupId);
    } else {
      editAppUserGroups[appId].push(groupId);
    }
  }

  function removeCreateAppPolicy(appIdx, polIdx) {
    createApps[appIdx].policies = createApps[appIdx].policies.filter((_, i) => i !== polIdx);
    createApps = createApps;
  }

  function toggleMethod(rule, method) {
    if (rule.methods.includes(method)) {
      rule.methods = rule.methods.filter(m => m !== method);
    } else {
      rule.methods = [...rule.methods, method];
    }
    polRules = polRules;
  }

  function toggleDomainMethod(rule, method) {
    if (rule.methods.includes(method)) {
      rule.methods = rule.methods.filter(m => m !== method);
    } else {
      rule.methods = [...rule.methods, method];
    }
  }

  function addPolicyRule() {
    polRules = [...polRules, makeRule()];
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

  function saveWizardPolicy() {
    const policy = {
      policy_id: polId || `pol-${Date.now()}`,
      name: polName,
      effect: polEffect,
      rules: polRules.map(r => ({
        resource_type: r.resourceType,
        resource_value: r.resourceValue,
        methods: r.methods,
        conditions: r.conditions,
      })),
    };

    if (policyTarget.startsWith('app:')) {
      const appId = policyTarget.slice(4);
      const apps = editApps.some(a => a.id === appId) ? editApps : createApps;
      const entry = apps.find(a => a.id === appId);
      if (!entry) return;
      if (editingPolicyIndex >= 0) {
        // Edit existing policy
        entry.policies[editingPolicyIndex] = policy;
      } else {
        // Add new policy
        entry.policies = [...entry.policies, policy];
      }
      editApps = editApps;
      createApps = createApps;
    }
    polId = '';
    polName = '';
    polEffect = 'Allow';
    polRules = [makeRule()];
    showWizardPolicyForm = false;
    policyTarget = '';
    editingPolicyIndex = -1;
  }

  function editWizardPolicy(appId, polIdx) {
    const apps = editApps.some(a => a.id === appId) ? editApps : createApps;
    const entry = apps.find(a => a.id === appId);
    if (!entry) return;
    const pol = entry.policies[polIdx];
    if (!pol) return;

    editingPolicyIndex = polIdx;
    polId = pol.policy_id || pol.id || '';
    polName = pol.name || '';
    polEffect = pol.effect || 'Allow';
    polRules = (pol.rules || []).map(r => ({
      resourceType: r.resource_type || get_resource_type(r.resource),
      resourceValue: r.resource_value || get_resource_value(r.resource),
      methods: r.methods || [],
      conditions: (r.conditions || []).map(c => ({
        claim: c.claim || '',
        operator: c.operator || 'Equals',
        value: c.value || '',
      })),
    }));
    policyTarget = `app:${appId}`;
    showWizardPolicyForm = true;
  }

  function removeWizardPolicy(domainIdx, polIdx) {
    createDomains[domainIdx].policies = createDomains[domainIdx].policies.filter((_, i) => i !== polIdx);
    createDomains = createDomains;
  }

  function removeEditWizardPolicy(domainIdx, polIdx) {
    editDomains[domainIdx].policies = editDomains[domainIdx].policies.filter((_, i) => i !== polIdx);
    editDomains = editDomains;
  }

  async function submitCreateOrg() {
    creating = true;
    createError = '';
    try {
      const domainsObj = {};
      for (const d of createDomains) {
        if (!d.name.trim()) continue;
        domainsObj[d.name.trim()] = {
          upstream_base_url: d.upstreamUrl.trim(),
          upstream_timeout_ms: d.upstreamTimeout,
          auto_generate_tls: d.autoGenerateTls,
        };
      }

      const appsObj = {};
      for (const a of createApps) {
        if (!a.id.trim()) continue;
        appsObj[a.id.trim()] = {
          domains: a.domains,
          policies: a.policies,
        };
      }

      const userGroupsObj = {};
      for (const g of createUserGroups) {
        if (!g.id.trim()) continue;
        userGroupsObj[g.id.trim()] = {
          emails: g.emails.filter(e => e.trim()),
          email_patterns: g.emailPatterns.filter(p => p.trim()),
        };
      }

      await api.orgs.create({
        id: newId.trim(),
        name: newName.trim(),
        domains: domainsObj,
        apps: appsObj,
        user_groups: userGroupsObj,
        app_user_groups: createAppUserGroups,
        jwt_issuer: jwtIssuer.trim(),
        jwt_audience: jwtAudience.trim(),
        jwt_public_key: autoGenerateJwt ? null : jwtPublicKey || null,
        auto_generate_jwt_keys: autoGenerateJwt,
        cookie_name: cookieName || null,
        redirect_url: redirectUrl || null,
        idp_url: idpUrl || null,
        req_param_name: reqParamName || null,
        token_param_name: tokenParamName || null,
      });

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
    editingOrg = false;
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
    editingOrg = false;
    expandedDomain = '';
  }

  function toggleDomainExpand(domain) {
    expandedDomain = expandedDomain === domain ? '' : domain;
  }

  // --- Edit org ---
  function enterEditMode() {
    if (!orgDetail) return;
    editingOrg = true;
    editStep = 1;
    editError = '';

    editName = orgDetail.name || '';

    // Build editDomains from orgDetail.config.domains (object keyed by domain)
    editDomains = [];
    const domainObj = orgDetail.config.domains || {};
    for (const [domainName, domainCfg] of Object.entries(domainObj)) {
      const upstream = domainCfg.upstream || {};
      const tls = domainCfg.tls || {};
      editDomains.push({
        name: domainName,
        upstreamUrl: upstream.base_url || '',
        upstreamTimeout: upstream.timeout_ms || 5000,
        autoGenerateTls: tls.cert_pem ? false : true,
        tlsCertPem: tls.cert_pem || '',
        tlsKeyPem: tls.key_pem || '',
        policies: [],
      });
    }
    if (editDomains.length === 0) editDomains = [makeDomainEntry()];

    // Build editApps from orgDetail.config.apps (object keyed by app id)
    editApps = [];
    const appsObj = orgDetail.config.apps || {};
    for (const [appId, appCfg] of Object.entries(appsObj)) {
      // Convert policies from Redis format to edit format
      const policies = (appCfg.policies || []).map(pol => ({
        policy_id: pol.id || pol.policy_id || '',
        name: pol.name || '',
        effect: pol.effect || 'Allow',
        rules: (pol.rules || []).map(rule => {
          // Convert resource from {Prefix: "/"} format to resource_type/resource_value
          let resourceType = 'prefix';
          let resourceValue = '/';
          if (rule.resource) {
            if (rule.resource.Exact !== undefined) {
              resourceType = 'exact';
              resourceValue = rule.resource.Exact;
            } else if (rule.resource.Prefix !== undefined) {
              resourceType = 'prefix';
              resourceValue = rule.resource.Prefix;
            } else if (rule.resource.Glob !== undefined) {
              resourceType = 'glob';
              resourceValue = rule.resource.Glob;
            }
          } else if (rule.resource_type) {
            resourceType = rule.resource_type;
            resourceValue = rule.resource_value || '/';
          }
          return {
            resource_type: resourceType,
            resource_value: resourceValue,
            methods: rule.methods || [],
            conditions: (rule.conditions || []).map(c => ({
              claim: c.claim || '',
              operator: c.operator || 'Equals',
              value: c.value || '',
            })),
          };
        }),
      }));
      editApps.push({
        id: appId,
        domains: appCfg.domains || [],
        policies: policies,
      });
    }
    if (editApps.length === 0) editApps = [makeAppEntry()];

    // Build editUserGroups from orgDetail.config.user_groups
    editUserGroups = [];
    const userGroupsObj = orgDetail.config.user_groups || {};
    for (const [groupId, groupCfg] of Object.entries(userGroupsObj)) {
      editUserGroups.push({
        id: groupId,
        emails: groupCfg.emails || [],
        emailPatterns: groupCfg.email_patterns || [],
      });
    }
    if (editUserGroups.length === 0) editUserGroups = [makeUserGroupEntry()];

    // Build editAppUserGroups from orgDetail.config.app_user_groups
    editAppUserGroups = orgDetail.config.app_user_groups || {};

    editJwtIssuer = orgDetail.config.auth?.jwt_issuer || '';
    editJwtAudience = orgDetail.config.auth?.jwt_audience || '';
    editAutoGenerateJwt = false;
    editJwtPublicKey = orgDetail.config.auth?.jwt_public_key || '';
    editCookieName = orgDetail.config.auth?.cookie_name || '';
    editRedirectUrl = orgDetail.config.auth?.redirect_url || '';
    editIdpUrl = orgDetail.config.auth?.idp_url || '';
    editReqParamName = orgDetail.config.auth?.req_param_name || 'req';
    editTokenParamName = orgDetail.config.auth?.token_param_name || 'token';
  }

  function cancelEdit() {
    editingOrg = false;
    editError = '';
  }

  function addEditDomain() {
    editDomains = [...editDomains, makeDomainEntry()];
  }

  function removeEditDomain(i) {
    editDomains = editDomains.filter((_, idx) => idx !== i);
  }

  function addEditApp() {
    editApps = [...editApps, makeAppEntry()];
  }

  function removeEditApp(i) {
    editApps = editApps.filter((_, idx) => idx !== i);
  }

  function toggleEditAppDomain(app, domain) {
    if (app.domains.includes(domain)) {
      app.domains = app.domains.filter(d => d !== domain);
    } else {
      app.domains = [...app.domains, domain];
    }
  }

  function removeEditAppPolicy(appIdx, polIdx) {
    editApps[appIdx].policies = editApps[appIdx].policies.filter((_, i) => i !== polIdx);
    editApps = editApps;
  }

  async function submitEditOrg() {
    if (!selectedOrg) return;
    saving = true;
    editError = '';
    try {
      const domainsObj = {};
      for (const d of editDomains) {
        if (!d.name.trim()) continue;
        domainsObj[d.name.trim()] = {
          upstream_base_url: d.upstreamUrl.trim(),
          upstream_timeout_ms: d.upstreamTimeout,
          auto_generate_tls: d.autoGenerateTls,
        };
      }

      const appsObj = {};
      for (const a of editApps) {
        if (!a.id.trim()) continue;
        appsObj[a.id.trim()] = {
          domains: a.domains,
          policies: a.policies,
        };
      }

      const userGroupsObj = {};
      for (const g of editUserGroups) {
        if (!g.id.trim()) continue;
        userGroupsObj[g.id.trim()] = {
          emails: g.emails.filter(e => e.trim()),
          email_patterns: g.emailPatterns.filter(p => p.trim()),
        };
      }

      const payload = {
        name: editName.trim() || undefined,
        domains: Object.keys(domainsObj).length > 0 ? domainsObj : undefined,
        apps: Object.keys(appsObj).length > 0 ? appsObj : undefined,
        user_groups: userGroupsObj,
        app_user_groups: editAppUserGroups,
        jwt_issuer: editJwtIssuer.trim() || undefined,
        jwt_audience: editJwtAudience.trim() || undefined,
        jwt_public_key: editAutoGenerateJwt ? null : (editJwtPublicKey || undefined),
        auto_generate_jwt_keys: editAutoGenerateJwt,
        cookie_name: editCookieName || undefined,
        redirect_url: editRedirectUrl || undefined,
        idp_url: editIdpUrl || undefined,
        req_param_name: editReqParamName || undefined,
        token_param_name: editTokenParamName || undefined,
      };

      await api.orgs.update(selectedOrg.id, payload);

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
            {#each Object.entries(orgDetail.config.domains || {}) as [domainName, domainCfg]}
              <div class="domain-detail-card">
                <div class="domain-detail-header" role="button" tabindex="0" on:click={() => toggleDomainExpand(domainName)} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggleDomainExpand(domainName); }}>
                  <span class="domain-detail-name">{domainName}</span>
                  <div class="domain-detail-meta">
                    <span class="tag">{domainCfg.upstream?.base_url || 'No upstream'}</span>
                    <span class="expand-icon">{expandedDomain === domainName ? '\u25B2' : '\u25BC'}</span>
                  </div>
                </div>
                {#if expandedDomain === domainName}
                  <div class="domain-detail-body">
                    <div class="detail-grid">
                      <div>
                        <h4>Upstream</h4>
                        <p>URL: <code>{domainCfg.upstream?.base_url || '-'}</code></p>
                        <p>Timeout: {domainCfg.upstream?.timeout_ms || '-'}ms</p>
                      </div>
                      <div>
                        <h4>TLS</h4>
                        {#if domainCfg.tls?.cert_pem}
                          <p>Certificate provided</p>
                        {:else}
                          <p class="muted">No certificate</p>
                        {/if}
                      </div>
                    </div>
                  </div>
                {/if}
              </div>
            {:else}
              <span class="muted">No domains configured</span>
            {/each}
          </div>

          <!-- Apps -->
          <div class="detail-section">
            <h3>Apps</h3>
            {#each Object.entries(orgDetail.config.apps || {}) as [appId, appCfg]}
              <div class="domain-detail-card">
                <div class="domain-detail-header" role="button" tabindex="0" on:click={() => toggleDomainExpand(`app:${appId}`)} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggleDomainExpand(`app:${appId}`); }}>
                  <span class="domain-detail-name">{appId}</span>
                  <div class="domain-detail-meta">
                    <span class="tag">{appCfg.domains?.length || 0} domains</span>
                    <span class="badge">{appCfg.policies?.length || 0} policies</span>
                    <span class="expand-icon">{expandedDomain === `app:${appId}` ? '\u25B2' : '\u25BC'}</span>
                  </div>
                </div>
                {#if expandedDomain === `app:${appId}`}
                  <div class="domain-detail-body">
                    <div class="detail-grid">
                      <div>
                        <h4>Domains</h4>
                        {#each (appCfg.domains || []) as domain}
                          <span class="tag">{domain}</span>
                        {:else}
                          <span class="muted">No domains</span>
                        {/each}
                      </div>
                    </div>

                    <div class="domain-policies-section">
                      <h4>Policies</h4>
                      {#each (appCfg.policies || []) as pol}
                        <div class="policy-card">
                          <div class="policy-header">
                            <span class="policy-name">{pol.name}</span>
                            <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                          </div>
                          {#each pol.rules || [] as rule}
                            <div class="policy-rule">
                              <code>{rule.resource_type || get_resource_type(rule.resource)}: {rule.resource_value || get_resource_value(rule.resource)}</code>
                              <span>{rule.methods?.join(', ') || ''}</span>
                              {#if rule.conditions?.length}
                                <span>Conditions: {rule.conditions.length}</span>
                              {/if}
                            </div>
                          {/each}
                        </div>
                      {:else}
                        <span class="muted">No policies</span>
                      {/each}
                    </div>
                  </div>
                {/if}
              </div>
            {:else}
              <span class="muted">No apps configured</span>
            {/each}
          </div>

          <!-- Auth (org level) -->
          <div class="detail-section">
            <h3>Auth</h3>
            <p>Issuer: <code>{orgDetail.config.auth?.jwt_issuer || '-'}</code></p>
            <p>Audience: <code>{orgDetail.config.auth?.jwt_audience || '-'}</code></p>
            <p>Cookie Name: <code>{orgDetail.config.auth?.cookie_name || '-'}</code></p>
            <p>Redirect URL: <code>{orgDetail.config.auth?.redirect_url || '-'}</code></p>
            <p>IDP URL: <code>{orgDetail.config.auth?.idp_url || '-'}</code></p>
            <p>Request Param: <code>{orgDetail.config.auth?.req_param_name || 'req'}</code></p>
            <p>Token Param: <code>{orgDetail.config.auth?.token_param_name || 'token'}</code></p>
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
              {#each ['Basic Info', 'Domains', 'Apps', 'User Groups', 'Auth'] as step, i}
                <span class="step clickable" class:active={editStep === i + 1} class:done={editStep > i + 1} on:click={() => editStep = i + 1} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') editStep = i + 1; }}>
                  {i + 1}. {step}
                </span>
              {/each}
            </div>

            {#if editStep === 1}
              <div class="step-content">
                <label>Name <input bind:value={editName} placeholder="Organization name" /></label>
              </div>
            {:else if editStep === 2}
              <div class="step-content">
                <p class="muted">Configure each domain's upstream and TLS.</p>
                {#each editDomains as _, i}
                  <div class="domain-config-card">
                    <div class="domain-config-header">
                      <label class="domain-label">Domain
                        <input bind:value={editDomains[i].name} placeholder="app.example.com" />
                      </label>
                      {#if editDomains.length > 1}
                        <button class="btn-delete-sm" on:click={() => removeEditDomain(i)}>Remove domain</button>
                      {/if}
                    </div>
                    <div class="domain-config-body">
                      <div class="config-group">
                        <h4>Upstream</h4>
                        <label>URL <input bind:value={editDomains[i].upstreamUrl} placeholder="http://localhost:8080" /></label>
                        <label>Timeout (ms) <input type="number" bind:value={editDomains[i].upstreamTimeout} /></label>
                      </div>
                      <div class="config-group">
                        <h4>TLS</h4>
                        <label class="check-label">
                          <input type="checkbox" bind:checked={editDomains[i].autoGenerateTls} /> Auto-generate self-signed certificate
                        </label>
                        {#if !editDomains[i].autoGenerateTls}
                          <label>Certificate PEM <textarea bind:value={editDomains[i].tlsCertPem} rows="3" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
                          <label>Private Key PEM <textarea bind:value={editDomains[i].tlsKeyPem} rows="3" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>
                        {/if}
                      </div>
                    </div>
                  </div>
                {/each}
                <button class="btn-add-sm" on:click={addEditDomain}>+ Add Domain</button>
              </div>
            {:else if editStep === 3}
              <div class="step-content">
                <p class="muted">Define apps and assign domains to each app.</p>
                {#each editApps as _, i}
                  <div class="app-config-card">
                    <div class="app-config-header">
                      <label class="app-label">App ID
                        <input bind:value={editApps[i].id} readonly />
                      </label>
                      {#if editApps.length > 1}
                        <button class="btn-delete-sm" on:click={() => removeEditApp(i)}>Remove app</button>
                      {/if}
                    </div>
                    <div class="app-config-body">
                      <div class="config-group">
                        <h4>Domains</h4>
                        {#if editDomains.filter(d => d.name.trim()).length === 0}
                          <span class="muted">No domains configured yet. Add domains in the previous step.</span>
                        {:else}
                          {#each editDomains.filter(d => d.name.trim()) as domain}
                            <label class="check-label">
                              <input type="checkbox" checked={editApps[i].domains.includes(domain.name)} on:change={() => toggleEditAppDomain(editApps[i], domain.name)} /> {domain.name}
                            </label>
                          {/each}
                        {/if}
                      </div>
                      <div class="config-group">
                        <h4>Policies</h4>
                        {#each editApps[i].policies as pol, pi}
                          <div class="policy-card">
                            <div class="policy-header">
                              <span class="policy-name">{pol.name}</span>
                              <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                              <button class="btn-add-sm" on:click={() => editWizardPolicy(editApps[i].id, pi)}>Edit</button>
                              <button class="btn-delete-sm" on:click={() => removeEditAppPolicy(i, pi)}>Remove</button>
                            </div>
                            {#each pol.rules || [] as rule}
                              <div class="policy-rule">
                                <code>{rule.resource_type || get_resource_type(rule.resource)}: {rule.resource_value || get_resource_value(rule.resource)}</code>
                                <span>{rule.methods?.join(', ') || ''}</span>
                              </div>
                            {/each}
                          </div>
                        {/each}
                        <button class="btn-add-sm" on:click={() => { policyTarget = `app:${editApps[i].id}`; showWizardPolicyForm = true; }}>+ Add Policy</button>
                      </div>
                    </div>
                  </div>
                {/each}
                <button class="btn-add-sm" on:click={addEditApp}>+ Add App</button>
              </div>

            {:else if editStep === 4}
              <div class="step-content">
                <p class="muted">Define user groups with email patterns for matching users. Assign groups to apps to control access.</p>
                {#each editUserGroups as _, i}
                  <div class="user-group-card">
                    <div class="user-group-header">
                      <label class="group-label">Group ID
                        <input bind:value={editUserGroups[i].id} placeholder="e.g. admins, team-a" />
                      </label>
                      {#if editUserGroups.length > 1}
                        <button class="btn-delete-sm" on:click={() => removeEditUserGroup(i)}>Remove group</button>
                      {/if}
                    </div>
                    <div class="user-group-body">
                      <div class="config-group">
                        <h4>Exact Emails</h4>
                        {#each editUserGroups[i].emails as _, ei}
                          <div class="email-row">
                            <input bind:value={editUserGroups[i].emails[ei]} placeholder="user@example.com" />
                            <button class="btn-delete-sm" on:click={() => removeEditEmail(i, ei)}>x</button>
                          </div>
                        {/each}
                        <button class="btn-add-sm" on:click={() => addEditEmail(i)}>+ Add Email</button>
                      </div>
                      <div class="config-group">
                        <h4>Email Patterns</h4>
                        {#each editUserGroups[i].emailPatterns as _, pi}
                          <div class="email-row">
                            <input bind:value={editUserGroups[i].emailPatterns[pi]} placeholder="e.g. *@company.com, team-*@org.io" />
                            <button class="btn-delete-sm" on:click={() => removeEditEmailPattern(i, pi)}>x</button>
                          </div>
                        {/each}
                        <button class="btn-add-sm" on:click={() => addEditEmailPattern(i)}>+ Add Pattern</button>
                      </div>
                      <div class="config-group">
                        <h4>Assign to Apps</h4>
                        {#if editApps.filter(a => a.id.trim()).length === 0}
                          <span class="muted">No apps configured yet. Add apps in the previous step.</span>
                        {:else}
                          {#each editApps.filter(a => a.id.trim()) as app}
                            <label class="check-label">
                              <input type="checkbox" checked={isEditGroupAssignedToApp(editUserGroups[i].id, app.id)} on:change={() => toggleEditGroupAppAssignment(editUserGroups[i].id, app.id)} /> {app.id}
                            </label>
                          {/each}
                        {/if}
                      </div>
                    </div>
                  </div>
                {/each}
                <button class="btn-add-sm" on:click={addEditUserGroup}>+ Add User Group</button>
              </div>

            {:else if editStep === 5}
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
                <label>Request Parameter Name <input bind:value={editReqParamName} placeholder="req" /></label>
                <label>Token Parameter Name <input bind:value={editTokenParamName} placeholder="token" /></label>
              </div>
            {/if}

            <div class="wizard-nav">
              {#if editStep > 1}
                <button class="btn-cancel" on:click={() => editStep--}>Back</button>
              {/if}
              {#if editStep < 5}
                <button class="btn-save" on:click={() => editStep++}>Next</button>
              {/if}
              <button class="btn-save" on:click={submitEditOrg} disabled={saving}>
                {saving ? 'Saving...' : 'Save'}
              </button>
              <button class="btn-cancel" on:click={cancelEdit}>Cancel</button>
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
          {#each ['Basic Info', 'Domains', 'Apps', 'User Groups', 'Auth'] as step, i}
            <span class="step clickable" class:active={createStep === i + 1} class:done={createStep > i + 1} on:click={() => createStep = i + 1} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') createStep = i + 1; }}>
              {i + 1}. {step}
            </span>
          {/each}
        </div>

        <!-- Step 1: Basic Info -->
        {#if createStep === 1}
          <div class="step-content">
            <label>Org ID <input bind:value={newId} placeholder="auto-generated" readonly /></label>
            <label>Name <input bind:value={newName} placeholder="My Organization" required /></label>
          </div>

        <!-- Step 2: Domains -->
        {:else if createStep === 2}
          <div class="step-content">
            <p class="muted">Configure each domain's upstream and TLS.</p>
            {#each createDomains as _, i}
              <div class="domain-config-card">
                <div class="domain-config-header">
                  <label class="domain-label">Domain
                    <input bind:value={createDomains[i].name} placeholder="app.example.com" />
                  </label>
                  {#if createDomains.length > 1}
                    <button class="btn-delete-sm" on:click={() => removeCreateDomain(i)}>Remove domain</button>
                  {/if}
                </div>
                <div class="domain-config-body">
                  <div class="config-group">
                    <h4>Upstream</h4>
                    <label>URL <input bind:value={createDomains[i].upstreamUrl} placeholder="http://localhost:8080" /></label>
                    <label>Timeout (ms) <input type="number" bind:value={createDomains[i].upstreamTimeout} /></label>
                  </div>
                  <div class="config-group">
                    <h4>TLS</h4>
                    <label class="check-label">
                      <input type="checkbox" bind:checked={createDomains[i].autoGenerateTls} /> Auto-generate self-signed certificate
                    </label>
                    {#if !createDomains[i].autoGenerateTls}
                      <label>Certificate PEM <textarea bind:value={createDomains[i].tlsCertPem} rows="3" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
                      <label>Private Key PEM <textarea bind:value={createDomains[i].tlsKeyPem} rows="3" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>
                    {/if}
                  </div>
                </div>
              </div>
            {/each}
            <button class="btn-add-sm" on:click={addCreateDomain}>+ Add Domain</button>
          </div>

        <!-- Step 3: Apps -->
        {:else if createStep === 3}
          <div class="step-content">
            <p class="muted">Define apps and assign domains to each app.</p>
            {#each createApps as _, i}
              <div class="app-config-card">
                <div class="app-config-header">
                  <label class="app-label">App ID
                    <input bind:value={createApps[i].id} readonly />
                  </label>
                  {#if createApps.length > 1}
                    <button class="btn-delete-sm" on:click={() => removeCreateApp(i)}>Remove app</button>
                  {/if}
                </div>
                <div class="app-config-body">
                  <div class="config-group">
                    <h4>Domains</h4>
                    {#if createDomains.filter(d => d.name.trim()).length === 0}
                      <span class="muted">No domains configured yet. Add domains in the previous step.</span>
                    {:else}
                      {#each createDomains.filter(d => d.name.trim()) as domain}
                        <label class="check-label">
                          <input type="checkbox" checked={createApps[i].domains.includes(domain.name)} on:change={() => toggleAppDomain(createApps[i], domain.name)} /> {domain.name}
                        </label>
                      {/each}
                    {/if}
                  </div>
                  <div class="config-group">
                    <h4>Policies</h4>
                    {#each createApps[i].policies as pol, pi}
                      <div class="policy-card">
                        <div class="policy-header">
                          <span class="policy-name">{pol.name}</span>
                          <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                          <button class="btn-add-sm" on:click={() => editWizardPolicy(createApps[i].id, pi)}>Edit</button>
                          <button class="btn-delete-sm" on:click={() => removeCreateAppPolicy(i, pi)}>Remove</button>
                        </div>
                        {#each pol.rules as rule}
                          <div class="policy-rule">
                            <code>{rule.resource_type}: {rule.resource_value}</code>
                            <span>{rule.methods.join(', ')}</span>
                          </div>
                        {/each}
                      </div>
                    {/each}
                    <button class="btn-add-sm" on:click={() => { policyTarget = `app:${createApps[i].id}`; showWizardPolicyForm = true; }}>+ Add Policy</button>
                  </div>
                </div>
              </div>
            {/each}
            <button class="btn-add-sm" on:click={addCreateApp}>+ Add App</button>
          </div>

        <!-- Step 4: User Groups -->
        {:else if createStep === 4}
          <div class="step-content">
            <p class="muted">Define user groups with email patterns for matching users. Assign groups to apps to control access.</p>
            {#each createUserGroups as _, i}
              <div class="user-group-card">
                <div class="user-group-header">
                  <label class="group-label">Group ID
                    <input bind:value={createUserGroups[i].id} placeholder="e.g. admins, team-a" />
                  </label>
                  {#if createUserGroups.length > 1}
                    <button class="btn-delete-sm" on:click={() => removeUserGroup(i)}>Remove group</button>
                  {/if}
                </div>
                <div class="user-group-body">
                  <div class="config-group">
                    <h4>Exact Emails</h4>
                    {#each createUserGroups[i].emails as _, ei}
                      <div class="email-row">
                        <input bind:value={createUserGroups[i].emails[ei]} placeholder="user@example.com" />
                        <button class="btn-delete-sm" on:click={() => removeEmail(i, ei)}>x</button>
                      </div>
                    {/each}
                    <button class="btn-add-sm" on:click={() => addEmail(i)}>+ Add Email</button>
                  </div>
                  <div class="config-group">
                    <h4>Email Patterns</h4>
                    {#each createUserGroups[i].emailPatterns as _, pi}
                      <div class="email-row">
                        <input bind:value={createUserGroups[i].emailPatterns[pi]} placeholder="e.g. *@company.com, team-*@org.io" />
                        <button class="btn-delete-sm" on:click={() => removeEmailPattern(i, pi)}>x</button>
                      </div>
                    {/each}
                    <button class="btn-add-sm" on:click={() => addEmailPattern(i)}>+ Add Pattern</button>
                  </div>
                  <div class="config-group">
                    <h4>Assign to Apps</h4>
                    {#if createApps.filter(a => a.id.trim()).length === 0}
                      <span class="muted">No apps configured yet. Add apps in the previous step.</span>
                    {:else}
                      {#each createApps.filter(a => a.id.trim()) as app}
                        <label class="check-label">
                          <input type="checkbox" checked={isGroupAssignedToApp(createUserGroups[i].id, app.id)} on:change={() => toggleGroupAppAssignment(createUserGroups[i].id, app.id)} /> {app.id}
                        </label>
                      {/each}
                    {/if}
                  </div>
                </div>
              </div>
            {/each}
            <button class="btn-add-sm" on:click={addUserGroup}>+ Add User Group</button>
          </div>

        <!-- Step 5: Auth -->
        {:else if createStep === 5}
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
            <label>Request Parameter Name <input bind:value={reqParamName} placeholder="req" /></label>
            <label>Token Parameter Name <input bind:value={tokenParamName} placeholder="token" /></label>
          </div>
        {/if}

        <!-- Wizard policy form (for both create and edit) -->
        {#if showWizardPolicyForm}
          <div class="policy-form card">
            <h3>{editingPolicyIndex >= 0 ? 'Edit' : 'Add'} Policy to <code>{policyTarget}</code></h3>
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
              <button class="btn-save" on:click={saveWizardPolicy}>Save Policy</button>
              <button class="btn-cancel" on:click={() => { showWizardPolicyForm = false; policyTarget = ''; editingPolicyIndex = -1; }}>Cancel</button>
            </div>
          </div>
        {/if}

        <!-- Navigation -->
        <div class="wizard-nav">
          {#if createStep > 1}
            <button class="btn-cancel" on:click={() => createStep--}>Back</button>
          {/if}
          {#if createStep < 5}
            <button class="btn-save" on:click={() => createStep++}>Next</button>
          {/if}
          <button class="btn-create" on:click={submitCreateOrg} disabled={creating}>
            {creating ? 'Creating...' : 'Create'}
          </button>
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
                  {#each Object.keys(org.config?.domains || {}).slice(0, 3) as d}
                    <span class="tag">{d}</span>
                  {/each}
                  {#if Object.keys(org.config?.domains || {}).length > 3}
                    <span class="muted">+{Object.keys(org.config?.domains || {}).length - 3} more</span>
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
  .actions { white-space: nowrap; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .section-header h2 { margin: 0; }

  button { padding: 0.35rem 0.7rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85rem; margin-right: 0.3rem; }
  .btn-logout { background: #95a5a6; color: white; }
  .btn-create { background: #27ae60; color: white; padding: 0.5rem 1rem; font-size: 0.95rem; }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
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
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  /* Domain detail card */
  .domain-detail-card { background: #f8f9fa; border: 1px solid #eee; border-radius: 6px; margin: 0.5rem 0; }
  .domain-detail-header { display: flex; justify-content: space-between; align-items: center; padding: 0.8rem 1rem; cursor: pointer; }
  .domain-detail-header:hover { background: #f0f0f0; }
  .domain-detail-name { font-weight: 600; }
  .domain-detail-meta { display: flex; align-items: center; gap: 0.5rem; }
  .expand-icon { font-size: 0.75rem; color: #999; }
  .domain-detail-body { padding: 0 1rem 1rem; border-top: 1px solid #eee; }
  .domain-policies-section { margin-top: 0.8rem; }
  .domain-policies-section h4 { margin-bottom: 0.5rem; }

  /* Domain config card (wizard) */
  .domain-config-card { background: #f8f9fa; border: 1px solid #ddd; border-radius: 6px; margin: 0.6rem 0; }
  .domain-config-header { display: flex; justify-content: space-between; align-items: flex-end; padding: 0.6rem 0.8rem; background: #f0f0f0; border-radius: 6px 6px 0 0; }
  .domain-label { margin: 0; font-weight: 600; }
  .domain-config-body { padding: 0.6rem 0.8rem; }
  .config-group { margin-bottom: 0.6rem; padding-bottom: 0.4rem; }
  .config-group h4 { margin: 0.3rem 0; color: #555; }

  /* App config card (wizard) */
  .app-config-card { background: #f8f9fa; border: 1px solid #ddd; border-radius: 6px; margin: 0.6rem 0; }
  .app-config-header { display: flex; justify-content: space-between; align-items: flex-end; padding: 0.6rem 0.8rem; background: #f0f0f0; border-radius: 6px 6px 0 0; }
  .app-label { margin: 0; font-weight: 600; }
  .app-config-body { padding: 0.6rem 0.8rem; }

  /* User Group card (wizard) */
  .user-group-card { background: #f8f9fa; border: 1px solid #ddd; border-radius: 6px; margin: 0.6rem 0; }
  .user-group-header { display: flex; justify-content: space-between; align-items: flex-end; padding: 0.6rem 0.8rem; background: #f0f0f0; border-radius: 6px 6px 0 0; }
  .group-label { margin: 0; font-weight: 600; }
  .user-group-body { padding: 0.6rem 0.8rem; }
  .email-row { display: flex; gap: 0.4rem; align-items: center; margin: 0.3rem 0; }
  .email-row input { flex: 1; }

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
  .condition-row { display: flex; gap: 0.4rem; align-items: center; margin: 0.3rem 0; }
  .condition-row input, .condition-row select { width: auto; flex: 1; }
  .form-actions { display: flex; gap: 0.5rem; margin-top: 1rem; }
  .policy-form { margin-top: 1rem; }
  .rule-card { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 0.8rem; margin: 0.5rem 0; }
  .conditions { margin-top: 0.5rem; }
  .conditions > span { font-size: 0.85rem; color: #666; }

  /* Wizard */
  .steps { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid #eee; }
  .step { padding: 0.4rem 0.8rem; border-radius: 20px; background: #f0f0f0; color: #888; font-size: 0.85rem; }
  .step.clickable { cursor: pointer; transition: background 0.2s, color 0.2s; }
  .step.clickable:hover { background: #e0e0e0; color: #555; }
  .step.active { background: #3498db; color: white; }
  .step.done { background: #27ae60; color: white; }
  .step-content { min-height: 200px; }
  .wizard-nav { display: flex; gap: 0.5rem; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #eee; }
  .edit-wizard { margin-top: 1rem; }
</style>
