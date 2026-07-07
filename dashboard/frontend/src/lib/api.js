import { get } from 'svelte/store';
import { authStore } from './auth.js';

const BASE = '/api';

async function request(path, options = {}) {
  const { token } = get(authStore);
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || err.message || 'Request failed');
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  signup: (email, password) =>
    request('/auth/signup', { method: 'POST', body: JSON.stringify({ email, password }) }),

  login: (email, password) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

  me: () => request('/auth/me'),

  admin: {
    listUsers: () => request('/admin/users'),
    approveUser: (id) => request(`/admin/users/${id}/approve`, { method: 'PUT' }),
    deleteUser: (id) => request(`/admin/users/${id}`, { method: 'DELETE' }),
    listOrgs: () => request('/admin/organizations'),
  },

  orgs: {
    list: () => request('/organizations'),
    get: (id) => request(`/organizations/${id}`),
    create: (data) =>
      request('/organizations', { method: 'POST', body: JSON.stringify(data) }),
    updateRaw: (id, data) =>
      request(`/organizations/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id) => request(`/organizations/${id}`, { method: 'DELETE' }),
    addPolicy: (id, data) =>
      request(`/organizations/${id}/policies`, { method: 'POST', body: JSON.stringify(data) }),
    removePolicy: (id, policyId) =>
      request(`/organizations/${id}/policies/${policyId}`, { method: 'DELETE' }),
    addDomainPolicy: (id, data) =>
      request(`/organizations/${id}/domain-policies`, { method: 'POST', body: JSON.stringify(data) }),
    removeDomainPolicy: (id, domain, policyId) =>
      request(`/organizations/${id}/domain-policies/${domain}/${policyId}`, { method: 'DELETE' }),
  },
};
