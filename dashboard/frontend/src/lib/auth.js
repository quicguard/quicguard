import { writable } from 'svelte/store';

function createAuthStore() {
  const stored = typeof localStorage !== 'undefined'
    ? localStorage.getItem('auth')
    : null;
  const initial = stored ? JSON.parse(stored) : { token: null, user: null };

  const { subscribe, set } = writable(initial);

  return {
    subscribe,
    /** @param {string} token @param {object} user */
    login: (token, user) => {
      const state = { token, user };
      localStorage.setItem('auth', JSON.stringify(state));
      set(state);
    },
    logout: () => {
      localStorage.removeItem('auth');
      set({ token: null, user: null });
    },
  };
}

export const authStore = createAuthStore();
