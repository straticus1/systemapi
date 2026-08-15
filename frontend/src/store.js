import { create } from 'zustand';
import { FleetAPI, api } from './api';

// Zustand Store for global app state (Auth, Hosts, Active terminals)
export const useAppStore = create((set, get) => ({
  apiKey: localStorage.getItem('systemapi_key') || '',
  isAuthenticated: !!localStorage.getItem('systemapi_key'),
  user: null, // OAuth user info
  authMethod: localStorage.getItem('systemapi_key') ? 'api_key' : null,

  hosts: [],
  isLoadingHosts: false,
  error: null,

  // Real-time telemetry tracking
  telemetryStream: null,

  setApiKey: (key) => {
    localStorage.setItem('systemapi_key', key);
    set({ apiKey: key, isAuthenticated: true, authMethod: key === 'oauth_session' ? 'oauth' : 'api_key' });
  },

  setUser: (user) => {
    set({ user, isAuthenticated: true, authMethod: 'oauth' });
  },

  logout: async () => {
    const { authMethod } = get();

    // If OAuth session, redirect to OAuth logout
    if (authMethod === 'oauth') {
      window.location.href = '/oauth/logout';
    } else {
      // API key logout
      localStorage.removeItem('systemapi_key');
      set({ apiKey: '', isAuthenticated: false, hosts: [], user: null, authMethod: null });
    }
  },

  checkSession: async () => {
    try {
      const res = await api.get('/oauth/user');
      if (res.data.authenticated) {
        set({
          user: res.data.user,
          isAuthenticated: true,
          authMethod: 'oauth'
        });
        return true;
      }
    } catch (err) {
      // Not authenticated via OAuth
    }
    return false;
  },

  fetchHosts: async () => {
    set({ isLoadingHosts: true, error: null });
    try {
      const data = await FleetAPI.getHosts();
      set({ hosts: data.hosts, isLoadingHosts: false });
    } catch (err) {
      set({ error: err.message || 'Failed to fetch fleet', isLoadingHosts: false });
    }
  },
  
  // Update a single host's stats from the WebSocket
  updateHostTelemetry: (hostId, telemetry) => set((state) => {
    const existingIdx = state.hosts.findIndex(h => h.host_id === hostId);
    
    // If it's a new host we haven't seen from REST API, we should fetch again or inject it
    if (existingIdx === -1) return state;
    
    const newHosts = [...state.hosts];
    // Attach the live telemetry to the REST object
    newHosts[existingIdx] = {
        ...newHosts[existingIdx],
        live_stats: telemetry,
        status: 'online',
        last_seen_at: new Date().toISOString()
    };
    
    return { hosts: newHosts };
  })
}));
