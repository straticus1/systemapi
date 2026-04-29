import axios from 'axios';

// Create a globally configured Axios instance
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 10000,
});

// Interceptor to inject API keys or JWT tokens if we have them
api.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('systemapi_key');
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey;
  }
  return config;
});

// Fleet API wrappers
export const FleetAPI = {
  getHosts: async () => {
    const res = await api.get('/api/v1/fleet');
    return res.data;
  },
  executeScript: async (hostId, script, entitlements = { allow_exec: false }) => {
    const res = await api.post(`/api/v1/fleet/${hostId}/execute`, { script, entitlements });
    return res.data;
  }
};
