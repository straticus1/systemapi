import { create } from 'zustand';
import { FleetAPI } from './api';

// Zustand Store for global app state (Auth, Hosts, Active terminals)
export const useAppStore = create((set, get) => ({
  apiKey: localStorage.getItem('systemapi_key') || '',
  isAuthenticated: !!localStorage.getItem('systemapi_key'),
  
  hosts: [],
  isLoadingHosts: false,
  error: null,
  
  // Real-time telemetry tracking
  telemetryStream: null,
  
  setApiKey: (key) => {
    localStorage.setItem('systemapi_key', key);
    set({ apiKey: key, isAuthenticated: true });
  },
  
  logout: () => {
    localStorage.removeItem('systemapi_key');
    set({ apiKey: '', isAuthenticated: false, hosts: [] });
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
