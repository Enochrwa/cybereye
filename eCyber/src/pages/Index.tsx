import React, { useEffect, useState, useRef } from 'react';
import { Shield, Terminal, AlertTriangle, Activity, Zap, Eye, Lock, Cpu, Globe, Server, Wifi, Target, Crosshair, Radar, Satellite, Brain, Binary, CircuitBoard, Usb, FileX, Flame, Bug, Database, Network, Radio, Signal, Camera, Headphones, Play } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { RootState } from "@/app/store";
import { setAuthModalState } from "@/app/slices/displaySlice"
import { useSelector, useDispatch } from "react-redux"
import AuthModal from './AuthModal';
import DemoVideo from "../utils/DemoVideo"
import { Link } from "react-router-dom";

const Index = () => {
  const dispatch = useDispatch();
  const isAuthModalOpen = useSelector((state: RootState) => state.display.isAuthModalOpen);

  const [isVideoOpen, setIsVideoOpen] = useState(false);
  const [text, setText] = useState('');
  const [matrixChars, setMatrixChars] = useState([]);
  const [threatCount, setThreatCount] = useState(847291);
  const [systemStatus, setSystemStatus] = useState('SCANNING');
  const [activeThreats, setActiveThreats] = useState([]);
  const [glitchText, setGlitchText] = useState('CYBER PROTECTION');
  const [networkNodes, setNetworkNodes] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanProgress, setScanProgress] = useState(0);
  const canvasRef = useRef(null);

  const fullText = 'Advanced threat analysis engine initialized... Scanning 847,291 endpoints across 195 countries... AI threat detection ACTIVE... Real-time protection ENABLED...';

  const threatTypes = [
    'MALWARE ATTACK', 'PHISHING ATTEMPT', 'UNAUTHORIZED ACCESS', 
    'DATA BREACH', 'DDoS ATTACK', 'INSIDER THREAT',
    'ZERO-DAY EXPLOIT', 'RANSOMWARE', 'CREDENTIAL THEFT'
  ];

  const countries = ['USA', 'UK', 'GERMANY', 'FRANCE', 'JAPAN', 'CANADA', 'AUSTRALIA', 'BRAZIL', 'INDIA', 'SOUTH AFRICA'];

  // Matrix rain effect - toned down
  useEffect(() => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');
    const matrix = [];
    for (let i = 0; i < 50; i++) {
      matrix.push({
        id: i,
        x: Math.random() * 100,
        char: chars[Math.floor(Math.random() * chars.length)],
        delay: Math.random() * 3,
        speed: 0.5 + Math.random() * 2
      });
    }
    setMatrixChars(matrix);
  }, []);

  // Network visualization
  useEffect(() => {
    const nodes = [];
    for (let i = 0; i < 20; i++) {
      nodes.push({
        id: i,
        x: Math.random() * 100,
        y: Math.random() * 100,
        connections: Math.floor(Math.random() * 4) + 1,
        status: Math.random() > 0.8 ? 'threat' : Math.random() > 0.9 ? 'warning' : 'secure'
      });
    }
    setNetworkNodes(nodes);
  }, []);

  // Typing effect
  useEffect(() => {
    let i = 0;
    const typingInterval = setInterval(() => {
      if (i < fullText.length) {
        setText(fullText.substring(0, i + 1));
        i++;
      } else {
        clearInterval(typingInterval);
        setSystemStatus('OPERATIONAL');
      }
    }, 30);

    return () => clearInterval(typingInterval);
  }, []);

  // Real-time threat simulation
  useEffect(() => {
    const threatInterval = setInterval(() => {
      setThreatCount(prev => prev + Math.floor(Math.random() * 7) + 1);
      
      // Generate new threats
      const newThreat = {
        id: Date.now(),
        type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
        country: countries[Math.floor(Math.random() * countries.length)],
        severity: Math.random() > 0.7 ? 'CRITICAL' : Math.random() > 0.4 ? 'HIGH' : 'MEDIUM',
        ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      };
      
      setActiveThreats(prev => [newThreat, ...prev.slice(0, 3)]);
    }, 3000);

    return () => clearInterval(threatInterval);
  }, []);

  // Glitch effect for main title
  useEffect(() => {
    const glitchInterval = setInterval(() => {
      const glitchChars = '!@#$%^&*()_+-=[]{}|;:,.<>?1234567890';
      const originalText = 'CYBER PROTECTION';
      let glitched = originalText;
      
      if (Math.random() > 0.9) {
        glitched = originalText.split('').map(char => 
          Math.random() > 0.8 ? glitchChars[Math.floor(Math.random() * glitchChars.length)] : char
        ).join('');
        
        setTimeout(() => setGlitchText(originalText), 100);
      }
      
      setGlitchText(glitched);
    }, 500);

    return () => clearInterval(glitchInterval);
  }, []);

  // Scan progress simulation
  useEffect(() => {
    const scanInterval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.random() * 2;
        return newProgress > 100 ? 0 : newProgress;
      });
    }, 200);

    return () => clearInterval(scanInterval);
  }, []);

  // Alert system
  useEffect(() => {
    const alertInterval = setInterval(() => {
      const alertTypes = [
        'THREAT DETECTED',
        'MALWARE FOUND',
        'UNAUTHORIZED ACCESS',
        'SUSPICIOUS TRAFFIC',
        'PHISHING ATTEMPT',
        'EXPLOIT BLOCKED'
      ];
      
      const newAlert = {
        id: Date.now(),
        message: alertTypes[Math.floor(Math.random() * alertTypes.length)],
        severity: Math.random() > 0.5 ? 'CRITICAL' : 'WARNING',
        timestamp: new Date().toLocaleTimeString()
      };
      
      setAlerts(prev => [newAlert, ...prev.slice(0, 2)]);
    }, 5000);

    return () => clearInterval(alertInterval);
  }, []);

  // Canvas network visualization
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width = window.innerWidth;
    const height = canvas.height = window.innerHeight;
    
    let animationId;
    
    const animate = () => {
      ctx.clearRect(0, 0, width, height);
      
      // Draw connections
      networkNodes.forEach((node, i) => {
        networkNodes.slice(i + 1).forEach(otherNode => {
          const distance = Math.sqrt(
            Math.pow((node.x - otherNode.x) * width / 100, 2) + 
            Math.pow((node.y - otherNode.y) * height / 100, 2)
          );
          
          if (distance < 200) {
            ctx.beginPath();
            ctx.moveTo(node.x * width / 100, node.y * height / 100);
            ctx.lineTo(otherNode.x * width / 100, otherNode.y * height / 100);
            ctx.strokeStyle = node.status === 'threat' || otherNode.status === 'threat' 
              ? 'rgba(239, 68, 68, 0.2)' 
              : 'rgba(34, 211, 238, 0.05)';
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        });
      });
      
      animationId = requestAnimationFrame(animate);
    };
    
    animate();
    
    return () => {
      if (animationId) cancelAnimationFrame(animationId);
    };
  }, [networkNodes]);

  const stats = [
    { label: 'THREATS STOPPED', value: threatCount.toLocaleString(), icon: Shield, color: 'text-red-400' },
    { label: 'GLOBAL ENDPOINTS', value: '847,291', icon: Globe, color: 'text-blue-400' },
    { label: 'RESPONSE TIME', value: '0.0003s', icon: Zap, color: 'text-yellow-400' },
    { label: 'AI ACCURACY', value: '99.97%', icon: Brain, color: 'text-purple-400' },
    { label: 'ENCRYPTION', value: '2048-BIT', icon: Lock, color: 'text-green-400' },
    { label: 'THREATS BLOCKED', value: '4,829', icon: Bug, color: 'text-orange-400' }
  ];

  return (
    <>
      <div className="min-h-screen bg-gray-900 text-cyan-100 font-sans overflow-hidden relative">
        {/* Canvas Background */}
        <canvas 
          ref={canvasRef}
          className="absolute inset-0 opacity-10 pointer-events-none"
          style={{ zIndex: 1 }}
        />
        
        {/* Matrix Background */}
        <div className="absolute inset-0 opacity-10" style={{ zIndex: 2 }}>
          {matrixChars.map((char) => (
            <motion.div
              key={char.id}
              className="absolute text-green-400 text-xs"
              style={{ left: `${char.x}%` }}
              animate={{
                y: ['0vh', '110vh'],
                opacity: [0, 1, 1, 0],
                scale: [0.5, 1, 1, 0.5]
              }}
              transition={{
                duration: 8 / char.speed,
                repeat: Infinity,
                delay: char.delay,
                ease: 'linear'
              }}
            >
              {char.char}
            </motion.div>
          ))}
        </div>

        {/* Grid Overlay */}
        <div className="absolute inset-0 opacity-5" style={{ zIndex: 3 }}>
          <div className="w-full h-full bg-gradient-to-br from-blue-500/10 via-transparent to-green-500/10"></div>
        </div>

        {/* Floating Alerts */}
        <AnimatePresence>
          {alerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ x: '100vw', opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: '-100vw', opacity: 0 }}
              className={`fixed top-20 right-4 z-50 p-4 border-l-4 backdrop-blur-md rounded-r-lg ${
                alert.severity === 'CRITICAL' 
                  ? 'bg-red-900/50 border-red-400 text-red-100' 
                  : 'bg-yellow-900/50 border-yellow-400 text-yellow-100'
              }`}
              style={{ top: `${80 + index * 80}px`, maxWidth: '90vw' }}
            >
              <div className="flex items-center space-x-2">
                <AlertTriangle className="animate-pulse" size={16} />
                <span className="text-xs font-bold">{alert.severity}</span>
              </div>
              <div className="text-xs mt-1">{alert.message}</div>
              <div className="text-xs opacity-60">{alert.timestamp}</div>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Header */}
        <motion.header 
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="relative z-40 flex flex-col sm:flex-row justify-between items-center px-4 sm:px-8 py-4 border-b border-cyan-500/20 backdrop-blur-md bg-gray-900/80"
        >
          <motion.div 
            className="flex items-center space-x-2 sm:space-x-4 mb-4 sm:mb-0"
            whileHover={{ scale: 1.02 }}
          >
            <motion.div
              animate={{ 
                rotate: 360,
              }}
              transition={{ 
                rotate: { duration: 4, repeat: Infinity, ease: 'linear' },
              }}
              className="relative"
            >
              <Shield className="text-cyan-400" size={32} />
            </motion.div>
            <div>
              <span className="text-xl sm:text-2xl font-bold tracking-wider text-transparent bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text">
                eCyber
              </span>
              <div className="text-xs text-green-400 animate-pulse flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                [{systemStatus}]
              </div>
            </div>
          </motion.div>

          <nav className="space-x-2 sm:space-x-4 md:space-x-6 text-xs sm:text-sm mb-4 sm:mb-0">
            {['THREATS', 'NETWORK', 'DASHBOARD'].map((item, i) => (
              <Link
                key={item}
                to={`/${item.toLowerCase()}`}
                className="relative group cursor-pointer inline-block mx-1"
                whileHover={{ scale: 1.1 }}
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
              >
                <span className="text-cyan-300 hover:text-blue-400 transition-colors font-medium">
                  {item}
                </span>
              </Link>
            ))}
          </nav>

          <div className="flex items-center space-x-2 sm:space-x-4">
            <motion.button
              onClick={() => dispatch(setAuthModalState(!isAuthModalOpen))}
              whileHover={{ 
                scale: 1.05, 
              }}
              whileTap={{ scale: 0.95 }}
              className="px-4 py-2 sm:px-6 sm:py-2 border border-cyan-400 text-cyan-400 hover:bg-cyan-500/10 transition-all duration-200 backdrop-blur-sm font-medium tracking-wider text-xs sm:text-sm"
            >
              SIGN IN
            </motion.button>
            <motion.button
              onClick={() => setIsVideoOpen(!isVideoOpen)}
              whileHover={{ 
                scale: 1.05,
              }}
              whileTap={{ scale: 0.95 }}
              className="px-4 py-2 sm:px-6 sm:py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium hover:from-cyan-400 hover:to-blue-500 transition-all duration-200 tracking-wider text-xs sm:text-sm"
            >
              <span>
              Get Demo
              
              
              </span>
            </motion.button>
          </div>
        </motion.header>

        {/* Hero Section */}
        <main className="relative z-30 flex flex-col items-center justify-center text-center py-8 px-4">
          <motion.div
            initial={{ scale: 0.3, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 1.5, delay: 0.2 }}
            className="mb-4 sm:mb-6"
          >
            <h1 className="text-3xl sm:text-5xl md:text-7xl font-bold tracking-tight mb-4 sm:mb-6 relative">
              <motion.span 
                className="text-transparent bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text"
              >
                REAL-TIME
              </motion.span>
              <br />
              <motion.span 
                className="text-transparent bg-gradient-to-r from-cyan-400 to-green-400 bg-clip-text"
              >
                {glitchText}
              </motion.span>
              <br />
              <motion.span 
                className="text-transparent bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text"
              >
                NETWORK
              </motion.span>
            </h1>
          </motion.div>

          {/* Live Scan Progress */}
          <motion.div
            initial={{ opacity: 0, width: 0 }}
            animate={{ opacity: 1, width: '100%' }}
            transition={{ delay: 1 }}
            className="w-full max-w-4xl mb-6 sm:mb-8"
          >
            <div className="flex justify-between text-xs mb-2">
              <span className="text-cyan-400">GLOBAL SCAN PROGRESS</span>
              <span className="text-green-400">{Math.floor(scanProgress)}%</span>
            </div>
            <div className="w-full bg-gray-800 h-2 relative overflow-hidden rounded-full">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </motion.div>

          {/* Terminal Output */}
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8 }}
            className="mb-6 sm:mb-8 w-full max-w-6xl"
          >
            <div className="text-sm sm:text-base text-cyan-300 h-12 flex items-center justify-center">
              <Terminal className="mr-2 text-green-400 animate-pulse" size={20} />
              <span className="text-center truncate">{text}</span>
              <span className="animate-pulse text-blue-400 ml-1 text-xl">█</span>
            </div>
          </motion.div>

          {/* Active Threats */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1.2 }}
            className="mb-6 sm:mb-8 w-full max-w-6xl"
          >
            <div className="text-blue-400 text-lg sm:text-xl font-bold mb-3 sm:mb-4 flex items-center justify-center">
              <AlertTriangle className="mr-2 animate-pulse" />
              LIVE THREAT FEED
              <AlertTriangle className="ml-2 animate-pulse" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {activeThreats.map((threat) => (
                <motion.div
                  key={threat.id}
                  initial={{ opacity: 0, x: -100 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 100 }}
                  className={`bg-gray-800/60 backdrop-blur-sm border-l-4 p-3 rounded-r-lg ${
                    threat.severity === 'CRITICAL' 
                      ? 'border-red-500' 
                      : threat.severity === 'HIGH'
                      ? 'border-orange-500'
                      : 'border-yellow-500'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <div className={`text-xs sm:text-sm font-bold ${
                        threat.severity === 'CRITICAL' ? 'text-red-400' : 
                        threat.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                      }`}>
                        {threat.severity} - {threat.type}
                      </div>
                      <div className="text-xs text-cyan-300">From: {threat.country}</div>
                      <div className="text-xs text-gray-400">IP: {threat.ip}</div>
                    </div>
                    <div className={`text-xs px-2 py-1 rounded ${
                      threat.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-100' : 
                      threat.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-100' : 'bg-yellow-900/50 text-yellow-100'
                    }`}>
                      BLOCKED
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Stats Grid */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1.4 }}
            className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4 mb-8 sm:mb-12 w-full max-w-7xl"
          >
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 50 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1.6 + i * 0.1 }}
                whileHover={{ 
                  scale: 1.05, 
                }}
                className="bg-gray-800/60 backdrop-blur-sm border border-gray-700 p-4 text-center rounded-lg hover:border-cyan-400 transition-all duration-200"
              >
                <stat.icon className={`mx-auto mb-2 ${stat.color}`} size={24} />
                <div className="text-xl sm:text-2xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-xs text-cyan-300 tracking-wider">{stat.label}</div>
              </motion.div>
            ))}
          </motion.div>

          {/* Action Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 2 }}
            className="flex flex-col sm:flex-row gap-4 sm:gap-6 mb-8 sm:mb-12"
          >
            <motion.div
              whileHover={{ 
                scale: 1.05,
              }}
              whileTap={{ scale: 0.95 }}
            >
              <button className="px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-500 text-white font-bold text-sm sm:text-base hover:from-blue-500 hover:to-cyan-400 transition-all duration-200 tracking-wider rounded-lg">
                START PROTECTION
              </button>
            </motion.div>
            <motion.button
              whileHover={{ 
                scale: 1.05,
              }}
              whileTap={{ scale: 0.95 }}
              className="px-8 py-4 border-2 border-cyan-400 text-cyan-400 font-bold text-sm sm:text-base hover:bg-cyan-400/10 transition-all duration-200 tracking-wider rounded-lg"
            >
              SEE HOW IT WORKS
            </motion.button>
          </motion.div>

          {/* Terminal Window */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 2.5 }}
            className="w-full max-w-7xl bg-gray-900/80 backdrop-blur-sm border border-cyan-400/30 rounded-lg overflow-hidden relative"
          >
            {/* Terminal Header */}
            <div className="flex items-center justify-between px-4 sm:px-6 py-3 bg-gray-800 border-b border-cyan-400/20 relative">
              <div className="flex items-center space-x-2 sm:space-x-4">
                <div className="flex space-x-2">
                  <div className="w-3 h-3 bg-red-500 rounded-full"/>
                  <div className="w-3 h-3 bg-yellow-500 rounded-full"/>
                  <div className="w-3 h-3 bg-green-500 rounded-full"/>
                </div>
                <span className="text-green-400 font-mono text-sm sm:text-base font-bold">SECURITY-CONSOLE</span>
              </div>
              <div className="flex items-center space-x-2 sm:space-x-4 text-xs">
                <span className="text-blue-400">CPU: 42%</span>
                <span className="text-green-400">RAM: 32%</span>
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                  <span className="text-green-400">ACTIVE</span>
                </div>
              </div>
            </div>
            
            {/* Terminal Content */}
            <div className="p-4 sm:p-6 text-left text-xs sm:text-sm h-64 sm:h-80 overflow-y-auto space-y-2 font-mono">
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 2.7}} className="text-cyan-400">
                [SYSTEM] Security network initialized...
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 2.9}} className="text-green-400">
                [AI-CORE] Advanced ML model loaded
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.1}} className="text-blue-400">
                [GLOBAL] Monitoring endpoints in real-time
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.3}} className="text-purple-400">
                [INTEL] Threat intelligence active
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.5}} className="text-green-400">
                [DEFENSE] Exploit detection enabled
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.7}} className="text-blue-400 animate-pulse">
                [ALERT] Threats detected and neutralized
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.9}} className="text-green-400">
                [SUCCESS] Security database synced
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.1}} className="text-cyan-400">
                [STATUS] All defense systems operational
              </motion.p>
              <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.3}} className="text-green-400 font-bold">
                [SECURE] Network protected
              </motion.p>
            </div>
          </motion.div>
        </main>

        {/* Footer */}
        <motion.footer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 6 }}
          className="relative z-30 mt-auto py-6 px-4 text-xs sm:text-sm border-t border-cyan-500/20 text-center bg-gray-900/80"
        >
          <div className="flex flex-col sm:flex-row justify-between items-center">
            <span className="text-cyan-400 mb-2 sm:mb-0">
              &copy; {new Date().getFullYear()} eCyber Security Systems
            </span>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <span className="text-green-400">ENCRYPTION ACTIVE</span>
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              </div>
            </div>
          </div>
        </motion.footer>
      </div>
      <AuthModal/>
      <DemoVideo isVideoOpen={isVideoOpen} setIsVideoOpen={setIsVideoOpen}/>
    </>
  );
};

export default Index;