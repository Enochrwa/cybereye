// Fixed Electron preload script with proper ES module support and security
import { contextBridge, ipcRenderer } from 'electron';

// Define the API interface for type safety
interface ElectronAPI {
  // App information
  getAppInfo: () => Promise<{
    name: string;
    version: string;
    isDev: boolean;
    platform: string;
  }>;

  // Backend management
  getBackendStatus: () => Promise<{
    isRunning: boolean;
    port: number;
  }>;
  
  restartBackend: () => Promise<boolean>;

  // System information
  getSystemInfo: () => Promise<{
    platform: string;
    arch: string;
    version: string;
    memory: number;
  }>;

  // Window management
  minimizeWindow: () => void;
  maximizeWindow: () => void;
  closeWindow: () => void;
  
  // Notifications
  showNotification: (title: string, body: string) => void;
  
  // File operations (secure)
  selectFile: (options?: {
    title?: string;
    filters?: Array<{ name: string; extensions: string[] }>;
  }) => Promise<string | null>;
  
  selectDirectory: (options?: {
    title?: string;
  }) => Promise<string | null>;

  // Event listeners
  onBackendStatusChange: (callback: (status: { isRunning: boolean; port: number }) => void) => () => void;
  onAppUpdate: (callback: (info: { version: string; available: boolean }) => void) => () => void;
  
  // Security
  openExternal: (url: string) => Promise<void>;
}

// Validation helpers
const validateString = (value: unknown): value is string => {
  return typeof value === 'string' && value.length > 0;
};

const validateUrl = (url: string): boolean => {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};

// Secure IPC wrapper
class SecureIPC {
  private static readonly ALLOWED_CHANNELS = [
    'app:info',
    'backend:status',
    'backend:restart',
    'system:info',
    'window:minimize',
    'window:maximize',
    'window:close',
    'notification:show',
    'file:select',
    'directory:select',
    'external:open',
  ] as const;

  private static readonly ALLOWED_EVENTS = [
    'backend:status-changed',
    'app:update-available',
  ] as const;

  static async invoke<T>(channel: string, ...args: unknown[]): Promise<T> {
    if (!this.ALLOWED_CHANNELS.includes(channel as any)) {
      throw new Error(`Channel '${channel}' is not allowed`);
    }

    try {
      return await ipcRenderer.invoke(channel, ...args);
    } catch (error) {
      console.error(`IPC invoke failed for channel '${channel}':`, error);
      throw error;
    }
  }

  static on(channel: string, listener: (...args: any[]) => void): () => void {
    if (!this.ALLOWED_EVENTS.includes(channel as any)) {
      throw new Error(`Event channel '${channel}' is not allowed`);
    }

    const wrappedListener = (_event: Electron.IpcRendererEvent, ...args: any[]) => {
      listener(...args);
    };

    ipcRenderer.on(channel, wrappedListener);

    // Return cleanup function
    return () => {
      ipcRenderer.removeListener(channel, wrappedListener);
    };
  }

  static removeAllListeners(channel: string): void {
    if (!this.ALLOWED_EVENTS.includes(channel as any)) {
      throw new Error(`Event channel '${channel}' is not allowed`);
    }
    
    ipcRenderer.removeAllListeners(channel);
  }
}

// Implementation of the Electron API
const electronAPI: ElectronAPI = {
  // App information
  async getAppInfo() {
    return await SecureIPC.invoke('app:info');
  },

  // Backend management
  async getBackendStatus() {
    return await SecureIPC.invoke('backend:status');
  },

  async restartBackend() {
    return await SecureIPC.invoke('backend:restart');
  },

  // System information
  async getSystemInfo() {
    return await SecureIPC.invoke('system:info');
  },

  // Window management
  minimizeWindow() {
    SecureIPC.invoke('window:minimize').catch(console.error);
  },

  maximizeWindow() {
    SecureIPC.invoke('window:maximize').catch(console.error);
  },

  closeWindow() {
    SecureIPC.invoke('window:close').catch(console.error);
  },

  // Notifications
  showNotification(title: string, body: string) {
    if (!validateString(title) || !validateString(body)) {
      throw new Error('Invalid notification parameters');
    }

    SecureIPC.invoke('notification:show', { title, body }).catch(console.error);
  },

  // File operations
  async selectFile(options = {}) {
    return await SecureIPC.invoke('file:select', options);
  },

  async selectDirectory(options = {}) {
    return await SecureIPC.invoke('directory:select', options);
  },

  // Event listeners
  onBackendStatusChange(callback) {
    if (typeof callback !== 'function') {
      throw new Error('Callback must be a function');
    }

    return SecureIPC.on('backend:status-changed', callback);
  },

  onAppUpdate(callback) {
    if (typeof callback !== 'function') {
      throw new Error('Callback must be a function');
    }

    return SecureIPC.on('app:update-available', callback);
  },

  // Security
  async openExternal(url: string) {
    if (!validateString(url) || !validateUrl(url)) {
      throw new Error('Invalid URL provided');
    }

    return await SecureIPC.invoke('external:open', url);
  },
};

// Additional utilities for the renderer process
const electronUtils = {
  // Environment detection
  isDev: process.env.NODE_ENV === 'development',
  
  // Platform detection
  platform: process.platform,
  
  // Version information
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
  },

  // Logging utility for renderer process
  log: {
    info: (message: string, ...args: any[]) => {
      console.log(`[Renderer] ${message}`, ...args);
    },
    warn: (message: string, ...args: any[]) => {
      console.warn(`[Renderer] ${message}`, ...args);
    },
    error: (message: string, ...args: any[]) => {
      console.error(`[Renderer] ${message}`, ...args);
    },
  },

  // Performance monitoring
  performance: {
    mark: (name: string) => {
      if (typeof performance !== 'undefined' && performance.mark) {
        performance.mark(name);
      }
    },
    measure: (name: string, startMark: string, endMark: string) => {
      if (typeof performance !== 'undefined' && performance.measure) {
        performance.measure(name, startMark, endMark);
      }
    },
  },
};

// Expose APIs to the renderer process
try {
  contextBridge.exposeInMainWorld('electronAPI', electronAPI);
  contextBridge.exposeInMainWorld('electronUtils', electronUtils);
  
  console.log('Electron APIs exposed successfully');
} catch (error) {
  console.error('Failed to expose Electron APIs:', error);
}

// Type declarations for the renderer process
declare global {
  interface Window {
    electronAPI: ElectronAPI;
    electronUtils: typeof electronUtils;
  }
}

export type { ElectronAPI };

