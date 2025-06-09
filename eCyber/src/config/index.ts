// Frontend configuration management
interface Config {
  apiBaseUrl: string;
  socketUrl: string;
  nodeEnv: string;
  enableDebug: boolean;
  enableAnalytics: boolean;
  enableCSP: boolean;
  enableHttpsRedirect: boolean;
  enableServiceWorker: boolean;
  enableCodeSplitting: boolean;
  defaultTheme: string;
  enableAnimations: boolean;
  enableErrorReporting: boolean;
  sentryDsn?: string;
}

const getEnvVar = (key: string, defaultValue: string = ''): string => {
  return import.meta.env[key] || defaultValue;
};

const getBooleanEnvVar = (key: string, defaultValue: boolean = false): boolean => {
  const value = import.meta.env[key];
  if (value === undefined) return defaultValue;
  return value === 'true' || value === '1';
};

export const config: Config = {
  apiBaseUrl: getEnvVar('VITE_API_BASE_URL', 'http://localhost:8000/api'),
  socketUrl: getEnvVar('VITE_SOCKET_URL', 'http://localhost:8000'),
  nodeEnv: getEnvVar('VITE_NODE_ENV', 'development'),
  enableDebug: getBooleanEnvVar('VITE_ENABLE_DEBUG', true),
  enableAnalytics: getBooleanEnvVar('VITE_ENABLE_ANALYTICS', false),
  enableCSP: getBooleanEnvVar('VITE_ENABLE_CSP', false),
  enableHttpsRedirect: getBooleanEnvVar('VITE_ENABLE_HTTPS_REDIRECT', false),
  enableServiceWorker: getBooleanEnvVar('VITE_ENABLE_SERVICE_WORKER', false),
  enableCodeSplitting: getBooleanEnvVar('VITE_ENABLE_CODE_SPLITTING', true),
  defaultTheme: getEnvVar('VITE_DEFAULT_THEME', 'system'),
  enableAnimations: getBooleanEnvVar('VITE_ENABLE_ANIMATIONS', true),
  enableErrorReporting: getBooleanEnvVar('VITE_ENABLE_ERROR_REPORTING', false),
  sentryDsn: getEnvVar('VITE_SENTRY_DSN'),
};

// Validate configuration
export const validateConfig = (): void => {
  const requiredVars = ['apiBaseUrl', 'socketUrl'];
  const missing = requiredVars.filter(key => !config[key as keyof Config]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // Validate URLs
  try {
    new URL(config.apiBaseUrl);
    new URL(config.socketUrl);
  } catch (error) {
    throw new Error('Invalid URL format in configuration');
  }
};

// Development helpers
export const isDevelopment = config.nodeEnv === 'development';
export const isProduction = config.nodeEnv === 'production';
export const isDebugEnabled = config.enableDebug && isDevelopment;

// Log configuration in development
if (isDevelopment && config.enableDebug) {
  console.log('🔧 Frontend Configuration:', config);
}

export default config;

