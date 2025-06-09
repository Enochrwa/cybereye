import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const projectRoot = path.join(__dirname, '..');
const backendDistPath = path.join(projectRoot, '..', 'backend', 'dist', 'ecyber_backend_dist');
const targetPath = path.join(projectRoot, 'backend', 'dist', 'ecyber_backend_dist');

async function copyBackend() {
  try {
    console.log('Copying backend distribution...');
    console.log(`Source: ${backendDistPath}`);
    console.log(`Target: ${targetPath}`);
    
    // Check if source exists
    if (!await fs.pathExists(backendDistPath)) {
      console.error('Backend distribution not found. Please build the backend first with PyInstaller.');
      console.error('Run: cd ../backend && pyinstaller ecyber_backend.spec');
      process.exit(1);
    }
    
    // Ensure target directory exists
    await fs.ensureDir(path.dirname(targetPath));
    
    // Copy the backend distribution
    await fs.copy(backendDistPath, targetPath, {
      overwrite: true,
      preserveTimestamps: true
    });
    
    console.log('✅ Backend copied successfully!');
    
    // Make executable on Unix systems
    if (process.platform !== 'win32') {
      const executablePath = path.join(targetPath, 'ecyber_backend');
      if (await fs.pathExists(executablePath)) {
        await fs.chmod(executablePath, 0o755);
        console.log('✅ Backend executable permissions set');
      }
    }
    
  } catch (error) {
    console.error('❌ Error copying backend:', error.message);
    process.exit(1);
  }
}

copyBackend();