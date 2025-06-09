import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const CyberLoader = ({
  isLoading = true,
  size = "large",
  showProgress = true,
  onComplete = () => {}
}) => {
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState(0);
  const [completedPhases, setCompletedPhases] = useState([]);
  const [activeConnections, setActiveConnections] = useState(0);
  const [threatsDetected, setThreatsDetected] = useState(0);
  const [systemStatus, setSystemStatus] = useState('initializing');
  const [phaseDetails, setPhaseDetails] = useState({ details: '', icon: '', status: '' });

  const phases = [
    {
      label: "INITIALIZING THREAT DATABASE",
      duration: 2000,
      details: "Loading 2.4M threat signatures...",
      icon: "🛡️",
      status: "critical"
    },
    {
      label: "STARTING NETWORK MONITORING",
      duration: 1500,
      details: "Binding to network interfaces...",
      icon: "🌐",
      status: "active"
    },
    {
      label: "LOADING ML THREAT MODELS",
      duration: 3000,
      details: "Neural networks: 4/4 loaded",
      icon: "🧠",
      status: "processing"
    },
    {
      label: "INITIALIZING PACKET ANALYZER",
      duration: 1200,
      details: "Deep packet inspection ready",
      icon: "📊",
      status: "scanning"
    },
    {
      label: "STARTING INTRUSION DETECTION",
      duration: 1800,
      details: "IDS engines online",
      icon: "🚨",
      status: "monitoring"
    },
    {
      label: "CONNECTING THREAT FEEDS",
      duration: 2200,
      details: "Real-time feeds: 12/12 connected",
      icon: "📡",
      status: "syncing"
    },
    {
      label: "INITIALIZING SANDBOX ENVIRONMENT",
      duration: 1600,
      details: "Isolated analysis ready",
      icon: "🔬",
      status: "contained"
    },
    {
      label: "ESTABLISHING SIEM INTEGRATION",
      duration: 1400,
      details: "Event correlation active",
      icon: "🔗",
      status: "connected"
    },
    {
      label: "STARTING BEHAVIORAL ANALYSIS",
      duration: 1300,
      details: "User activity baselines loaded",
      icon: "👤",
      status: "learning"
    },
    {
      label: "ACTIVATING RESPONSE AUTOMATION",
      duration: 1000,
      details: "Playbooks ready for execution",
      icon: "⚡",
      status: "armed"
    }
  ];

  useEffect(() => {
    if (!isLoading) return;

    let phaseIndex = 0;
    let totalProgress = 0;

    const runPhase = () => {
      if (phaseIndex >= phases.length) {
        setProgress(100);
        setSystemStatus('operational');
        setTimeout(() => onComplete(), 500);
        return;
      }

      const currentPhaseData = phases[phaseIndex];
      setCurrentPhase(phaseIndex);
      setPhaseDetails({
        details: currentPhaseData.details,
        icon: currentPhaseData.icon,
        status: currentPhaseData.status
      });

      const phaseProgress = 100 / phases.length;
      const startProgress = totalProgress;
      const endProgress = totalProgress + phaseProgress;

      let phaseStartTime = Date.now();

      const progressInterval = setInterval(() => {
        const elapsed = Date.now() - phaseStartTime;
        const phaseCompletion = Math.min(elapsed / currentPhaseData.duration, 1);
        const currentProgress = startProgress + phaseProgress * phaseCompletion;

        setProgress(currentProgress);

        if (Math.random() > 0.7) {
          setActiveConnections(prev => Math.max(0, prev + Math.floor(Math.random() * 3) - 1));
        }

        if (Math.random() > 0.85 && phaseIndex > 2) {
          setThreatsDetected(prev => prev + 1);
        }

        if (phaseCompletion >= 1) {
          clearInterval(progressInterval);
          setCompletedPhases(prev => [...prev, phaseIndex]);
          totalProgress = endProgress;
          phaseIndex++;
          setTimeout(runPhase, 200);
        }
      }, 100);
    };

    const initialDelay = setTimeout(runPhase, 500);

    return () => {
      clearTimeout(initialDelay);
    };
  }, [isLoading, onComplete]);

  if (!isLoading) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950 overflow-hidden"
      >
        {/* Animated background grid */}
        <div className="absolute inset-0">
          <motion.div
            className="w-full h-full opacity-20"
            animate={{ 
              backgroundPosition: ['0px 0px', '50px 50px', '0px 0px'],
            }}
            transition={{ 
              duration: 20, 
              repeat: Infinity, 
              ease: "linear" 
            }}
            style={{
              backgroundImage: `
                radial-gradient(circle at 20% 50%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(34, 197, 94, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(168, 85, 247, 0.15) 0%, transparent 50%),
                linear-gradient(rgba(59, 130, 246, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(59, 130, 246, 0.05) 1px, transparent 1px)
              `,
              backgroundSize: '100% 100%, 100% 100%, 100% 100%, 40px 40px, 40px 40px'
            }}
          />
        </div>

        {/* Multiple scanning beams */}
        {[...Array(3)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute inset-0 pointer-events-none"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 1, 0] }}
            transition={{
              duration: 4 + i,
              repeat: Infinity,
              ease: "easeInOut",
              delay: i * 1.5
            }}
          >
            <motion.div
              className={`w-full h-0.5 bg-gradient-to-r from-transparent via-blue-400/60 to-transparent`}
              initial={{ y: '-10px' }}
              animate={{ y: '100vh' }}
              transition={{
                duration: 6 + i,
                repeat: Infinity,
                ease: "linear",
                delay: i * 2
              }}
            />
          </motion.div>
        ))}

        {/* Radar sweep with enhanced design */}
        <motion.div
          className="absolute inset-0 pointer-events-none flex items-center justify-center"
          animate={{ rotate: 360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
        >
          <div className="relative">
            {[300, 250, 200, 150].map((size, i) => (
              <motion.div
                key={i}
                className={`absolute -translate-x-1/2 -translate-y-1/2 rounded-full border border-blue-400/20`}
                style={{ width: size, height: size, left: '50%', top: '50%' }}
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ 
                  duration: 3 + i, 
                  repeat: Infinity, 
                  ease: "easeInOut",
                  delay: i * 0.5 
                }}
              />
            ))}
            <div className="absolute top-0 left-1/2 w-0.5 h-36 bg-gradient-to-b from-blue-400/80 via-emerald-400/60 to-transparent transform -translate-x-0.5" />
          </div>
        </motion.div>

        <div className="relative flex flex-col items-center space-y-8 p-8 max-w-5xl w-full">
          {/* Enhanced Main Loader */}
          <div className="relative">
            {/* Outer glow ring */}
            <motion.div
              className="absolute -inset-8 rounded-full bg-gradient-to-r from-blue-500/20 via-emerald-500/20 to-purple-500/20 blur-xl"
              animate={{ 
                scale: [1, 1.2, 1],
                rotate: [0, 180, 360] 
              }}
              transition={{ 
                duration: 8, 
                repeat: Infinity, 
                ease: "easeInOut" 
              }}
            />

            {/* Multiple rotating rings */}
            {[...Array(4)].map((_, i) => (
              <motion.div
                key={i}
                className={`absolute rounded-full border-2 ${
                  i === 0 ? 'w-40 h-40 border-blue-400/40' :
                  i === 1 ? 'w-32 h-32 border-emerald-400/40' :
                  i === 2 ? 'w-24 h-24 border-purple-400/40' :
                  'w-16 h-16 border-cyan-400/40'
                }`}
                style={{ 
                  left: '50%', 
                  top: '50%',
                  transform: 'translate(-50%, -50%)'
                }}
                animate={{ rotate: i % 2 === 0 ? 360 : -360 }}
                transition={{
                  duration: 8 + i * 2,
                  repeat: Infinity,
                  ease: "linear"
                }}
              >
                {/* Ring segments */}
                {[...Array(6)].map((_, segIndex) => (
                  <motion.div
                    key={segIndex}
                    className="absolute w-2 h-2 rounded-full bg-current"
                    style={{
                      left: '50%',
                      top: '0%',
                      transformOrigin: '0 50vh',
                      transform: `rotate(${segIndex * 60}deg) translateY(-50%)`
                    }}
                    animate={{ 
                      opacity: [0.3, 1, 0.3],
                      scale: [0.8, 1.2, 0.8]
                    }}
                    transition={{
                      duration: 2,
                      repeat: Infinity,
                      delay: segIndex * 0.1 + i * 0.2,
                      ease: "easeInOut"
                    }}
                  />
                ))}
              </motion.div>
            ))}

            {/* Center core with enhanced design */}
            <motion.div
              className="relative w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 via-emerald-500 to-purple-500 shadow-2xl"
              animate={{ 
                scale: [1, 1.1, 1],
                boxShadow: [
                  "0 0 20px rgba(59, 130, 246, 0.5)",
                  "0 0 40px rgba(34, 197, 94, 0.5)",
                  "0 0 20px rgba(168, 85, 247, 0.5)",
                  "0 0 20px rgba(59, 130, 246, 0.5)"
                ]
              }}
              transition={{ 
                duration: 3, 
                repeat: Infinity, 
                ease: "easeInOut" 
              }}
            >
              <div className="absolute inset-2 rounded-full bg-slate-900 flex items-center justify-center">
                <motion.span 
                  className="text-white font-mono font-bold text-xs select-none"
                  animate={{ opacity: [0.7, 1, 0.7] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  SOC
                </motion.span>
              </div>
            </motion.div>
          </div>

          {/* Enhanced Progress Section */}
          {showProgress && (
            <motion.div 
              className="w-full max-w-2xl space-y-4"
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.5 }}
            >
              {/* Progress bar with glow effect */}
              <div className="relative">
                <div className="w-full h-3 bg-slate-800/80 rounded-full border border-slate-700 overflow-hidden backdrop-blur-sm">
                  <motion.div
                    className="h-full bg-gradient-to-r from-blue-500 via-emerald-500 to-purple-500 relative"
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ ease: "easeOut", duration: 0.5 }}
                  >
                    <motion.div
                      className="absolute inset-0 bg-white/20"
                      animate={{ x: ['-100%', '100%'] }}
                      transition={{ 
                        duration: 2, 
                        repeat: Infinity, 
                        ease: "easeInOut" 
                      }}
                    />
                  </motion.div>
                </div>
                <motion.div
                  className="absolute -inset-1 rounded-full bg-gradient-to-r from-blue-500/20 via-emerald-500/20 to-purple-500/20 blur-sm -z-10"
                  animate={{ opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity }}
                />
              </div>
              
              {/* Progress percentage */}
              <div className="flex justify-between items-center text-sm">
                <motion.span 
                  className="text-emerald-400 font-mono font-semibold"
                  animate={{ opacity: [0.7, 1, 0.7] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                >
                  {Math.floor(progress)}% COMPLETE
                </motion.span>
                <span className="text-slate-400 font-mono text-xs">
                  {systemStatus.toUpperCase()}
                </span>
              </div>
            </motion.div>
          )}

          {/* Enhanced Phase Information */}
          <motion.div 
            className="w-full max-w-3xl bg-slate-900/90 backdrop-blur-md rounded-xl border border-slate-700/50 p-6 shadow-2xl"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            {/* Phase header */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-4">
                <motion.span 
                  className="text-3xl"
                  animate={{ rotate: [0, 10, -10, 0] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  {phaseDetails.icon}
                </motion.span>
                <div>
                  <h3 className="font-mono font-bold text-lg text-white">
                    {phases[currentPhase]?.label || "INITIALIZING..."}
                  </h3>
                  <p className="text-slate-400 text-sm font-mono">
                    {phaseDetails.details}
                  </p>
                </div>
              </div>
              
              <motion.span
                className={`px-3 py-1 rounded-full text-xs font-mono font-bold border ${
                  phaseDetails.status === "critical" ? "bg-red-500/20 border-red-500/50 text-red-300" :
                  phaseDetails.status === "active" ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-300" :
                  phaseDetails.status === "processing" ? "bg-yellow-500/20 border-yellow-500/50 text-yellow-300" :
                  phaseDetails.status === "scanning" ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-300" :
                  phaseDetails.status === "monitoring" ? "bg-blue-500/20 border-blue-500/50 text-blue-300" :
                  phaseDetails.status === "syncing" ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300" :
                  phaseDetails.status === "contained" ? "bg-purple-500/20 border-purple-500/50 text-purple-300" :
                  phaseDetails.status === "connected" ? "bg-teal-500/20 border-teal-500/50 text-teal-300" :
                  phaseDetails.status === "learning" ? "bg-orange-500/20 border-orange-500/50 text-orange-300" :
                  phaseDetails.status === "armed" ? "bg-pink-500/20 border-pink-500/50 text-pink-300" : 
                  "bg-slate-500/20 border-slate-500/50 text-slate-300"
                }`}
                animate={{ 
                  boxShadow: [
                    "0 0 5px rgba(59, 130, 246, 0.3)",
                    "0 0 20px rgba(59, 130, 246, 0.6)",
                    "0 0 5px rgba(59, 130, 246, 0.3)"
                  ]
                }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                {phaseDetails.status.toUpperCase()}
              </motion.span>
            </div>

            {/* Dynamic stats with enhanced styling */}
            <div className="grid grid-cols-3 gap-4 mt-6">
              {[
                { label: "Active Connections", value: activeConnections, color: "emerald" },
                { label: "Threats Detected", value: threatsDetected, color: "red" },
                { label: "System Status", value: systemStatus, color: "blue" }
              ].map((stat, i) => (
                <motion.div
                  key={i}
                  className={`bg-slate-800/50 rounded-lg p-3 border border-slate-700/30`}
                  initial={{ scale: 0.9, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.8 + i * 0.1 }}
                >
                  <div className="text-slate-400 text-xs font-mono uppercase tracking-wide">
                    {stat.label}
                  </div>
                  <motion.div
                    className={`text-${stat.color}-400 text-lg font-mono font-bold mt-1`}
                    animate={{ opacity: [0.7, 1, 0.7] }}
                    transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
                  >
                    {typeof stat.value === 'string' ? stat.value.toUpperCase() : stat.value}
                  </motion.div>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Enhanced Completed Phases */}
          <motion.div 
            className="w-full max-w-3xl bg-slate-900/70 backdrop-blur-md rounded-xl border border-slate-700/30 p-4 max-h-48 overflow-hidden"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 1 }}
          >
            <h4 className="text-emerald-400 font-mono font-semibold mb-3 flex items-center">
              <span className="w-2 h-2 bg-emerald-400 rounded-full mr-2 animate-pulse"></span>
              COMPLETED OPERATIONS
            </h4>
            <div className="space-y-1 max-h-32 overflow-y-auto custom-scrollbar">
              <AnimatePresence>
                {completedPhases.map(i => (
                  <motion.div
                    key={i}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    className="text-slate-300 text-sm font-mono flex items-center py-1"
                  >
                    <span className="text-emerald-400 mr-2">✓</span>
                    {phases[i]?.label}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </motion.div>
        </div>

      </motion.div>
    </AnimatePresence>
  );
};

export default CyberLoader;