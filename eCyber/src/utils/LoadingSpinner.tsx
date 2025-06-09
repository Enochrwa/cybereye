import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Loader2 } from 'lucide-react';

const LoadingSpinner = () => {
  const shimmerVariants = {
    initial: { x: '-100%' },
    animate: { 
      x: '100%',
      transition: {
        duration: 1.5,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  };

  const pulseVariants = {
    animate: {
      opacity: [0.3, 0.8, 0.3],
      transition: {
        duration: 2,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  };

  const SkeletonBox = ({ width, height, className = "" }) => (
    <div className={`relative bg-gray-800/50 rounded-lg overflow-hidden ${className}`} style={{ width, height }}>
      <motion.div
        variants={shimmerVariants}
        initial="initial"
        animate="animate"
        className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent"
      />
    </div>
  );

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800">
      <div className="w-full max-w-4xl mx-auto p-8">
        {/* Header Section */}
        <div className="bg-gray-900/80 backdrop-blur-sm border border-cyan-500/20 rounded-2xl p-8 mb-6 shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-4">
              <div className="relative">
                <motion.div
                  variants={pulseVariants}
                  animate="animate"
                  className="absolute inset-0 bg-cyan-500/30 rounded-full blur-sm"
                />
                <div className="relative bg-gray-800 border-2 border-cyan-500/50 rounded-full p-3">
                  <Shield className="w-6 h-6 text-cyan-400" />
                </div>
              </div>
              <div className="space-y-2">
                <SkeletonBox width="200px" height="24px" />
                <SkeletonBox width="150px" height="16px" />
              </div>
            </div>
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              className="text-cyan-400"
            >
              <Loader2 className="w-8 h-8" />
            </motion.div>
          </div>
          
          {/* Stats Row */}
          <div className="grid grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="text-center space-y-2">
                <SkeletonBox width="100%" height="32px" className="mx-auto" />
                <SkeletonBox width="80px" height="16px" className="mx-auto" />
              </div>
            ))}
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          {/* Left Panel */}
          <div className="lg:col-span-2 bg-gray-900/80 backdrop-blur-sm border border-cyan-500/20 rounded-2xl p-6 shadow-xl">
            <div className="space-y-6">
              {/* Chart Area */}
              <div className="space-y-3">
                <SkeletonBox width="180px" height="20px" />
                <div className="relative h-64 bg-gray-800/30 rounded-lg overflow-hidden">
                  <motion.div
                    variants={shimmerVariants}
                    initial="initial"
                    animate="animate"
                    className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-500/10 to-transparent"
                  />
                  {/* Fake chart lines */}
                  <div className="absolute inset-4 space-y-4">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <motion.div
                        key={i}
                        className="h-0.5 bg-gradient-to-r from-cyan-500/30 to-transparent rounded-full"
                        style={{ width: `${Math.random() * 80 + 20}%` }}
                        animate={{ opacity: [0.3, 0.7, 0.3] }}
                        transition={{ duration: 2, delay: i * 0.2, repeat: Infinity }}
                      />
                    ))}
                  </div>
                </div>
              </div>

              {/* Data Rows */}
              <div className="space-y-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="flex items-center justify-between p-4 bg-gray-800/20 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <SkeletonBox width="40px" height="40px" className="rounded-full" />
                      <div className="space-y-2">
                        <SkeletonBox width="120px" height="16px" />
                        <SkeletonBox width="80px" height="12px" />
                      </div>
                    </div>
                    <SkeletonBox width="60px" height="20px" />
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Panel */}
          <div className="space-y-6">
            {/* Activity Panel */}
            <div className="bg-gray-900/80 backdrop-blur-sm border border-cyan-500/20 rounded-2xl p-6 shadow-xl">
              <div className="space-y-4">
                <SkeletonBox width="140px" height="20px" />
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="flex items-center space-x-3 p-3 bg-gray-800/20 rounded-lg">
                    <SkeletonBox width="32px" height="32px" className="rounded-full" />
                    <div className="flex-1 space-y-2">
                      <SkeletonBox width="100%" height="14px" />
                      <SkeletonBox width="70%" height="12px" />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Status Panel */}
            <div className="bg-gray-900/80 backdrop-blur-sm border border-cyan-500/20 rounded-2xl p-6 shadow-xl">
              <div className="space-y-4">
                <SkeletonBox width="100px" height="20px" />
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="flex justify-between items-center">
                      <SkeletonBox width="80px" height="14px" />
                      <SkeletonBox width="40px" height="14px" />
                    </div>
                  ))}
                </div>
                <div className="pt-4 border-t border-gray-700/50">
                  <SkeletonBox width="100%" height="40px" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer Stats */}
        <div className="bg-gray-900/80 backdrop-blur-sm border border-cyan-500/20 rounded-2xl p-6 shadow-xl">
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="text-center space-y-2">
                <SkeletonBox width="100%" height="28px" />
                <SkeletonBox width="60px" height="14px" className="mx-auto" />
              </div>
            ))}
          </div>
        </div>

        {/* Loading Text */}
        <motion.div
          className="text-center mt-8"
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          <p className="text-cyan-400 text-lg font-medium">Loading Security services...</p>
          <p className="text-gray-500 text-sm mt-1">Wait a bit</p>
        </motion.div>

        {/* Floating Elements */}
        <div className="fixed inset-0 pointer-events-none overflow-hidden">
          {Array.from({ length: 8 }).map((_, i) => (
            <motion.div
              key={i}
              className="absolute w-2 h-2 bg-cyan-500/30 rounded-full"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
              }}
              animate={{
                y: [-20, 20],
                opacity: [0, 1, 0],
              }}
              transition={{
                duration: 3,
                delay: i * 0.5,
                repeat: Infinity,
                ease: 'easeInOut'
              }}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default LoadingSpinner;