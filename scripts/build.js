import { spawn } from 'child_process';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const projectRoot = path.join(__dirname, '..');

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    console.log(`Running: ${command} ${args.join(' ')}`);
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: true,
      ...options
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Command failed with exit code ${code}`));
      }
    });

    child.on('error', reject);
  });
}

async function buildApp() {
  try {
    console.log('🚀 Starting eCyber build process...');
    
    // Step 1: Clean previous builds
    console.log('\n📦 Cleaning previous builds...');
    await fs.remove(path.join(projectRoot, 'dist'));
    await fs.remove(path.join(projectRoot, 'dist_electron'));
    
    // Step 2: Build React frontend
    console.log('\n⚛️  Building React frontend...');
    await runCommand('npm', ['run', 'home-build'], { cwd: projectRoot });
    
    // Step 3: Copy backend if it exists
    console.log('\n🐍 Copying backend distribution...');
    try {
      await runCommand('npm', ['run', 'copy-backend'], { cwd: projectRoot });
    } catch (error) {
      console.warn('⚠️  Backend not found. Make sure to build it with PyInstaller first.');
      console.warn('   Run: cd ../backend && pyinstaller ecyber_backend.spec');
      process.exit(1);
    }
    
    // Step 4: Package with Electron Builder
    console.log('\n📱 Packaging with Electron Builder...');
    const platform = process.argv[2] || 'current';
    
    let buildArgs = ['run'];
    switch (platform) {
      case 'win':
        buildArgs.push('package:win');
        break;
      case 'mac':
        buildArgs.push('package:mac');
        break;
      case 'linux':
        buildArgs.push('package:linux');
        break;
      default:
        buildArgs.push('package');
    }
    
    await runCommand('npm', buildArgs, { cwd: projectRoot });
    
    console.log('\n✅ Build completed successfully!');
    console.log(`📁 Output directory: ${path.join(projectRoot, 'dist_electron')}`);
    
  } catch (error) {
    console.error('\n❌ Build failed:', error.message);
    process.exit(1);
  }
}

buildApp();