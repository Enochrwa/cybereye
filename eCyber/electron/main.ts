// Fixed Electron main process with proper error handling and security
import { app, BrowserWindow, Menu, ipcMain, dialog, shell } from 'electron';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import os from 'os';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Application configuration
const APP_CONFIG = {
  name: 'eCyber Security Platform',
  version: '1.0.0',
  isDev: !app.isPackaged,
  window: {
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
  },
  backend: {
    port: 8000,
    healthCheckInterval: 5000,
    maxRestartAttempts: 3,
    restartDelay: 2000,
  }
};

// Global variables
let mainWindow: BrowserWindow | null = null;
let backendProcess: ChildProcess | null = null;
let backendRestartAttempts = 0;
let healthCheckInterval: NodeJS.Timeout | null = null;
let isQuitting = false;

// Logging utility
class Logger {
  private static log(level: string, message: string, ...args: any[]) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${level}] ${message}`, ...args);
  }

  static info(message: string, ...args: any[]) {
    this.log('INFO', message, ...args);
  }

  static error(message: string, ...args: any[]) {
    this.log('ERROR', message, ...args);
  }

  static warn(message: string, ...args: any[]) {
    this.log('WARN', message, ...args);
  }

  static debug(message: string, ...args: any[]) {
    if (APP_CONFIG.isDev) {
      this.log('DEBUG', message, ...args);
    }
  }
}

// Backend process manager
class BackendManager {
  private process: ChildProcess | null = null;
  private isStarting = false;
  private restartAttempts = 0;

  async start(): Promise<boolean> {
    if (this.isStarting || this.process) {
      Logger.warn('Backend is already starting or running');
      return false;
    }

    this.isStarting = true;
    Logger.info('Starting backend process...');

    try {
      const backendPath = this.getBackendPath();
      if (!backendPath) {
        throw new Error('Backend executable not found');
      }

      this.process = spawn(backendPath.executable, backendPath.args, {
        cwd: backendPath.cwd,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          PYTHONUNBUFFERED: '1',
          ECYBER_ENV: APP_CONFIG.isDev ? 'development' : 'production',
        },
      });

      this.setupProcessHandlers();
      
      // Wait for backend to be ready
      const isReady = await this.waitForBackend();
      if (isReady) {
        this.restartAttempts = 0;
        Logger.info('Backend started successfully');
        this.startHealthCheck();
        return true;
      } else {
        throw new Error('Backend failed to start within timeout');
      }
    } catch (error) {
      Logger.error('Failed to start backend:', error);
      this.isStarting = false;
      return false;
    }
  }

  private getBackendPath(): { executable: string; args: string[]; cwd: string } | null {
    const platform = os.platform();
    
    if (APP_CONFIG.isDev) {
      // Development mode - use Python script
      const pythonExecutable = platform === 'win32' ? 'python.exe' : 'python3';
      const backendScript = path.join(__dirname, '../../backend/main.py');
      const venvPython = path.join(__dirname, '../../backend/venv/Scripts/python.exe');
      
      // Try virtual environment first
      if (fs.existsSync(venvPython)) {
        return {
          executable: venvPython,
          args: [backendScript],
          cwd: path.join(__dirname, '../../backend'),
        };
      }
      
      // Fallback to system Python
      if (fs.existsSync(backendScript)) {
        return {
          executable: pythonExecutable,
          args: [backendScript],
          cwd: path.join(__dirname, '../../backend'),
        };
      }
    } else {
      // Production mode - use bundled executable
      const exeName = platform === 'win32' ? 'backend_server.exe' : 'backend_server';
      const backendExe = path.join(process.resourcesPath, 'backend', exeName);
      
      if (fs.existsSync(backendExe)) {
        return {
          executable: backendExe,
          args: [],
          cwd: path.dirname(backendExe),
        };
      }
    }

    return null;
  }

  private setupProcessHandlers(): void {
    if (!this.process) return;

    this.process.stdout?.on('data', (data) => {
      const output = data.toString().trim();
      if (output) {
        Logger.info(`[Backend] ${output}`);
      }
    });

    this.process.stderr?.on('data', (data) => {
      const output = data.toString().trim();
      if (output && !output.includes('WARNING')) {
        Logger.error(`[Backend Error] ${output}`);
      }
    });

    this.process.on('close', (code, signal) => {
      Logger.info(`Backend process closed with code ${code}, signal ${signal}`);
      this.process = null;
      this.isStarting = false;
      this.stopHealthCheck();

      if (!isQuitting && code !== 0) {
        this.handleBackendCrash();
      }
    });

    this.process.on('error', (error) => {
      Logger.error('Backend process error:', error);
      this.process = null;
      this.isStarting = false;
      this.stopHealthCheck();
    });
  }

  private async waitForBackend(timeout = 30000): Promise<boolean> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        const response = await fetch(`http://localhost:${APP_CONFIG.backend.port}/health`);
        if (response.ok) {
          return true;
        }
      } catch (error) {
        // Backend not ready yet, continue waiting
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return false;
  }

  private startHealthCheck(): void {
    this.stopHealthCheck();
    
    healthCheckInterval = setInterval(async () => {
      try {
        const response = await fetch(`http://localhost:${APP_CONFIG.backend.port}/health`, {
          timeout: 5000,
        });
        
        if (!response.ok) {
          throw new Error(`Health check failed with status ${response.status}`);
        }
        
        // Reset restart attempts on successful health check
        this.restartAttempts = 0;
      } catch (error) {
        Logger.warn('Backend health check failed:', error);
        
        if (this.process) {
          this.handleBackendCrash();
        }
      }
    }, APP_CONFIG.backend.healthCheckInterval);
  }

  private stopHealthCheck(): void {
    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      healthCheckInterval = null;
    }
  }

  private async handleBackendCrash(): Promise<void> {
    if (this.restartAttempts >= APP_CONFIG.backend.maxRestartAttempts) {
      Logger.error('Backend restart attempts exceeded, giving up');
      
      if (mainWindow) {
        dialog.showErrorBox(
          'Backend Error',
          'The backend service has crashed and could not be restarted. Please restart the application.'
        );
      }
      return;
    }

    this.restartAttempts++;
    Logger.info(`Attempting to restart backend (attempt ${this.restartAttempts}/${APP_CONFIG.backend.maxRestartAttempts})`);
    
    await new Promise(resolve => setTimeout(resolve, APP_CONFIG.backend.restartDelay));
    await this.start();
  }

  stop(): void {
    this.stopHealthCheck();
    
    if (this.process) {
      Logger.info('Stopping backend process...');
      
      // Try graceful shutdown first
      this.process.kill('SIGTERM');
      
      // Force kill after timeout
      setTimeout(() => {
        if (this.process) {
          Logger.warn('Force killing backend process');
          this.process.kill('SIGKILL');
        }
      }, 5000);
      
      this.process = null;
    }
  }

  isRunning(): boolean {
    return this.process !== null && !this.process.killed;
  }
}

// Window manager
class WindowManager {
  private window: BrowserWindow | null = null;

  create(): BrowserWindow {
    Logger.info('Creating main window...');

    this.window = new BrowserWindow({
      width: APP_CONFIG.window.width,
      height: APP_CONFIG.window.height,
      minWidth: APP_CONFIG.window.minWidth,
      minHeight: APP_CONFIG.window.minHeight,
      show: false, // Don't show until ready
      icon: this.getIconPath(),
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        // enableRemoteModule: false,
        allowRunningInsecureContent: false,
        experimentalFeatures: false,
        webSecurity: true,
        preload: path.join(__dirname, 'preload.ts'),
      },
      titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    });

    this.setupWindowHandlers();
    this.loadContent();
    
    return this.window;
  }

  private getIconPath(): string {
    const platform = os.platform();
    const iconName = platform === 'win32' ? 'eCyber.ico' : 
                    platform === 'darwin' ? 'eCyber.icns' : 
                    'eCyber.png';
    
    return path.join(__dirname, '../public', iconName);
  }

  private setupWindowHandlers(): void {
    if (!this.window) return;

    this.window.once('ready-to-show', () => {
      Logger.info('Window ready to show');
      this.window?.show();
      
      if (APP_CONFIG.isDev) {
        this.window?.webContents.openDevTools();
      }
    });

    this.window.on('closed', () => {
      Logger.info('Window closed');
      this.window = null;
    });

    // Handle external links
    this.window.webContents.setWindowOpenHandler(({ url }) => {
      shell.openExternal(url);
      return { action: 'deny' };
    });

    // Security: prevent navigation to external sites
    this.window.webContents.on('will-navigate', (event, navigationUrl) => {
      const parsedUrl = new URL(navigationUrl);
      
      if (parsedUrl.origin !== 'http://localhost:4000' && 
          parsedUrl.origin !== 'http://localhost:8000') {
        event.preventDefault();
        Logger.warn('Prevented navigation to external URL:', navigationUrl);
      }
    });
  }

  private loadContent(): void {
    if (!this.window) return;

    if (APP_CONFIG.isDev) {
      // Development mode - load from dev server
      this.window.loadURL('http://localhost:4000').catch((error) => {
        Logger.error('Failed to load dev server:', error);
        // Fallback to built files
        this.loadBuiltFiles();
      });
    } else {
      this.loadBuiltFiles();
    }
  }

  private loadBuiltFiles(): void {
    if (!this.window) return;

    const indexPath = path.join(__dirname, '../dist/index.html');
    
    if (fs.existsSync(indexPath)) {
      this.window.loadFile(indexPath);
    } else {
      Logger.error('Built files not found');
      dialog.showErrorBox(
        'Application Error',
        'Application files are missing. Please reinstall the application.'
      );
    }
  }

  getWindow(): BrowserWindow | null {
    return this.window;
  }
}

// Application manager
class AppManager {
  private backendManager = new BackendManager();
  private windowManager = new WindowManager();

  async initialize(): Promise<void> {
    Logger.info(`Starting ${APP_CONFIG.name} v${APP_CONFIG.version}`);
    
    // Set app properties
    app.setName(APP_CONFIG.name);
    
    // Security: prevent new window creation
    app.on('web-contents-created', (event, contents) => {
      contents.on('new-window', (event, navigationUrl) => {
        event.preventDefault();
        shell.openExternal(navigationUrl);
      });
    });

    // Start backend first
    const backendStarted = await this.backendManager.start();
    if (!backendStarted) {
      dialog.showErrorBox(
        'Startup Error',
        'Failed to start the backend service. Please check your installation.'
      );
      app.quit();
      return;
    }

    // Create main window
    mainWindow = this.windowManager.create();
    
    // Setup application menu
    this.setupMenu();
    
    // Setup IPC handlers
    this.setupIPC();
  }

  private setupMenu(): void {
    const template: Electron.MenuItemConstructorOptions[] = [
      {
        label: 'File',
        submenu: [
          {
            label: 'Quit',
            accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
            click: () => app.quit(),
          },
        ],
      },
      {
        label: 'Edit',
        submenu: [
          { role: 'undo' },
          { role: 'redo' },
          { type: 'separator' },
          { role: 'cut' },
          { role: 'copy' },
          { role: 'paste' },
          { role: 'selectAll' },
        ],
      },
      {
        label: 'View',
        submenu: [
          { role: 'reload' },
          { role: 'forceReload' },
          { role: 'toggleDevTools' },
          { type: 'separator' },
          { role: 'resetZoom' },
          { role: 'zoomIn' },
          { role: 'zoomOut' },
          { type: 'separator' },
          { role: 'togglefullscreen' },
        ],
      },
      {
        label: 'Help',
        submenu: [
          {
            label: 'About',
            click: () => {
              dialog.showMessageBox(mainWindow!, {
                type: 'info',
                title: 'About',
                message: APP_CONFIG.name,
                detail: `Version: ${APP_CONFIG.version}\nElectron: ${process.versions.electron}\nNode: ${process.versions.node}`,
              });
            },
          },
        ],
      },
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
  }

  private setupIPC(): void {
    // Backend status
    ipcMain.handle('backend:status', () => {
      return {
        isRunning: this.backendManager.isRunning(),
        port: APP_CONFIG.backend.port,
      };
    });

    // App info
    ipcMain.handle('app:info', () => {
      return {
        name: APP_CONFIG.name,
        version: APP_CONFIG.version,
        isDev: APP_CONFIG.isDev,
        platform: os.platform(),
      };
    });

    // Restart backend
    ipcMain.handle('backend:restart', async () => {
      Logger.info('Restarting backend via IPC');
      this.backendManager.stop();
      await new Promise(resolve => setTimeout(resolve, 2000));
      return await this.backendManager.start();
    });
  }

  shutdown(): void {
    Logger.info('Shutting down application...');
    isQuitting = true;
    this.backendManager.stop();
  }
}

// Application instance
const appManager = new AppManager();

// App event handlers
app.whenReady().then(() => {
  appManager.initialize().catch((error) => {
    Logger.error('Failed to initialize app:', error);
    app.quit();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    appManager.initialize();
  }
});

app.on('before-quit', () => {
  appManager.shutdown();
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  Logger.error('Uncaught exception:', error);
  dialog.showErrorBox('Unexpected Error', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
  Logger.error('Unhandled rejection at:', promise, 'reason:', reason);
});

export { APP_CONFIG, Logger };

