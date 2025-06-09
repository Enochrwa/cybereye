import axios from 'axios';

// Vite provides `import.meta.env.DEV` to check for development mode
// Vite also provides `import.meta.env.PROD` to check for production mode (opposite of DEV)
const isDevelopment = import.meta.env.DEV;

// Backend URL when running in production/packaged mode
const PROD_BACKEND_URL = 'https://ecyber-backend.onrender.com';

const apiClient = axios.create({
  baseURL: isDevelopment ? '/' : PROD_BACKEND_URL,
});

// You can add interceptors here if needed for auth tokens, error handling, etc.
// For example:
// apiClient.interceptors.request.use(config => {
//   // const token = localStorage.getItem('token');
//   // if (token) {
//   //   config.headers.Authorization = `Bearer ${token}`;
//   // }
//   return config;
// });

export default apiClient;
