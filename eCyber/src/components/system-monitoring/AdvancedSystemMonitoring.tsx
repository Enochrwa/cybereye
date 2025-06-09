import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight, Shield, Cpu, Database, Lock, Globe, Server, AlertTriangle, Network, Activity, Monitor, ArrowRight, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const Index = () => {
  // Animated text typing effect for the hero subtitle
  const [text, setText] = React.useState('');
  const fullText = "Advanced network monitoring, threat detection, and AI-powered incident response for the modern enterprise.";
  
  useEffect(() => {
    let i = 0;
    const typingInterval = setInterval(() => {
      if (i < fullText.length) {
        setText(fullText.substring(0, i + 1));
        i++;
      } else {
        clearInterval(typingInterval);
      }
    }, 50);
    
    return () => clearInterval(typingInterval);
  }, []);
  
  return (
    <div className="min-h-screen bg-gradient-to-b from-isimbi-navy via-isimbi-navy to-isimbi-dark-charcoal">
      {/* Header */}
      <header className="container mx-auto px-4 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <div className="h-10 w-10 rounded-md bg-isimbi-purple flex items-center justify-center">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="text-2xl font-bold text-white ml-2 tracking-wider">ISIMBI</span>
          </div>
          <nav className="hidden md:flex space-x-8 text-sm">
            <a href="#features" className="text-gray-300 hover:text-white transition-colors">Features</a>
            <a href="#about" className="text-gray-300 hover:text-white transition-colors">About</a>
            <a href="#security" className="text-gray-300 hover:text-white transition-colors">Security</a>
            <a href="#contact" className="text-gray-300 hover:text-white transition-colors">Contact</a>
          </nav>
          <div className="flex items-center space-x-4">
            <div className="relative group">
              <Button variant="ghost" className="text-gray-300 hover:text-white relative overflow-hidden">
                <span className="relative z-10">Sign In</span>
                <span className="absolute bottom-0 left-0 w-full h-[2px] bg-isimbi-purple scale-x-0 group-hover:scale-x-100 transition-transform origin-bottom-left"></span>
              </Button>
            </div>
            <Button className="bg-isimbi-purple hover:bg-isimbi-purple/90 shadow-lg shadow-isimbi-purple/20">
              Request Demo
            </Button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 md:py-32 flex flex-col items-center justify-center text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="max-w-4xl mx-auto"
        >
          <div className="inline-block mb-4">
            <Badge variant="outline" className="px-4 py-1.5 text-sm font-medium bg-isimbi-purple/10 text-isimbi-purple border-isimbi-purple/30">
              New: Version 3.5 Released
            </Badge>
          </div>
          
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold text-white leading-tight mb-6 tracking-tight">
            ISIMBI — <span className="bg-gradient-to-r from-isimbi-purple to-isimbi-bright-blue bg-clip-text text-transparent">Intelligent Security</span>, Built for the New Era
          </h1>
          
          <p className="text-xl md:text-2xl text-gray-300 mb-10 max-w-3xl mx-auto h-16 font-light">
            {text}<span className="animate-pulse">|</span>
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
            <Link to="/dashboard">
              <Button size="lg" className="bg-isimbi-bright-blue hover:bg-isimbi-bright-blue/90 text-white px-8 shadow-lg shadow-isimbi-bright-blue/20 text-lg group relative overflow-hidden">
                <span className="relative z-10 flex items-center">
                  Explore Dashboard
                  <ChevronRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                </span>
                <span className="absolute inset-0 bg-gradient-to-r from-isimbi-bright-blue to-isimbi-bright-blue/80 opacity-0 group-hover:opacity-100 transition-opacity"></span>
              </Button>
            </Link>
            <Button variant="outline" size="lg" className="border-gray-600 text-white hover:bg-white/5 text-lg group relative overflow-hidden">
              <span className="relative z-10 flex items-center">
                Watch Demo
                <span className="ml-2 h-5 w-5 flex items-center justify-center rounded-full bg-white/10 group-hover:bg-white/20 transition-colors">
                  ▶
                </span>
              </span>
            </Button>
          </div>
          
          <div className="flex justify-center mt-8 space-x-6 text-sm text-gray-400">
            <div className="flex items-center">
              <Shield className="h-4 w-4 mr-1 text-isimbi-purple" />
              <span>Enterprise-grade</span>
            </div>
            <div className="flex items-center">
              <Lock className="h-4 w-4 mr-1 text-isimbi-purple" />
              <span>ISO 27001 Certified</span>
            </div>
            <div className="flex items-center">
              <Server className="h-4 w-4 mr-1 text-isimbi-purple" />
              <span>99.9% Uptime</span>
            </div>
          </div>
        </motion.div>

        {/* Animated visualization */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5, duration: 1.5 }}
          className="mt-16 relative w-full max-w-5xl h-64 sm:h-80 md:h-96"
        >
          {/* Enhanced 3D network visualization */}
          <div className="absolute inset-0 flex items-center justify-center perspective-1000">
            <div className="relative w-full h-full max-w-2xl">
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-40 h-40 sm:w-60 sm:h-60 rounded-full border border-isimbi-purple/30 animate-spin" style={{animationDuration: '15s'}}></div>
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-60 h-60 sm:w-80 sm:h-80 rounded-full border border-isimbi-bright-blue/20 rotate-45 animate-spin" style={{animationDuration: '25s'}}></div>
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-80 h-80 sm:w-96 sm:h-96 rounded-full border border-isimbi-bright-blue/10 -rotate-12 animate-spin" style={{animationDuration: '40s'}}></div>
              
              {/* Center globe */}
              <motion.div 
                className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-16 h-16 md:w-20 md:h-20 rounded-full bg-gradient-to-r from-isimbi-purple to-isimbi-bright-blue blur-sm animate-float"
                animate={{ 
                  boxShadow: ["0 0 10px rgba(155, 135, 245, 0.5)", "0 0 30px rgba(155, 135, 245, 0.8)", "0 0 10px rgba(155, 135, 245, 0.5)"] 
                }}
                transition={{ duration: 3, repeat: Infinity }}
              />
              
              {/* Nodes */}
              {[...Array(16)].map((_, i) => {
                const angle = (i / 16) * Math.PI * 2;
                const radius = 120 + (i % 3) * 40;
                const x = Math.cos(angle) * radius;
                const y = Math.sin(angle) * radius;
                return (
                  <motion.div
                    key={i}
                    className="absolute top-1/2 left-1/2 w-3 h-3 rounded-full bg-isimbi-bright-blue/80"
                    style={{ 
                      left: `calc(50% + ${x}px)`, 
                      top: `calc(50% + ${y}px)` 
                    }}
                    animate={{
                      scale: [1, 1.2, 1],
                      opacity: [0.7, 1, 0.7]
                    }}
                    transition={{
                      repeat: Infinity,
                      duration: 2 + i * 0.1,
                      delay: i * 0.2
                    }}
                  />
                );
              })}
              
              {/* Connecting lines with animation */}
              {[...Array(6)].map((_, i) => {
                const rotation = i * 30;
                return (
                  <motion.div 
                    key={i} 
                    className="absolute top-1/2 left-1/2 w-full h-0.5 bg-gradient-to-r from-transparent via-isimbi-bright-blue/30 to-transparent transform -translate-x-1/2 -translate-y-1/2"
                    style={{ rotate: `${rotation}deg` }}
                    animate={{
                      opacity: [0.3, 0.7, 0.3],
                    }}
                    transition={{
                      repeat: Infinity,
                      duration: 3 + i,
                      ease: "easeInOut"
                    }}
                  />
                );
              })}
              
              {/* Ripple effect */}
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                <div className="absolute w-16 h-16 rounded-full border border-isimbi-bright-blue/30 animate-ping" style={{ animationDuration: "3s" }}></div>
                <div className="absolute w-16 h-16 rounded-full border border-isimbi-purple/20 animate-ping" style={{ animationDuration: "4s", animationDelay: "1s" }}></div>
              </div>
            </div>
          </div>
          
          {/* Moving particles */}
          {[...Array(10)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute h-2 w-2 rounded-full bg-isimbi-bright-blue"
              style={{ 
                left: Math.random() * 100 + '%',
                top: Math.random() * 100 + '%',
                opacity: 0,
              }}
              animate={{ 
                opacity: [0, 0.8, 0],
                scale: [0, 1, 0],
                x: Math.random() * 200 - 100,
                y: Math.random() * 200 - 100,
              }}
              transition={{ 
                repeat: Infinity, 
                duration: 3,
                delay: i * 0.7,
                ease: "easeInOut" 
              }}
            />
          ))}
          
          {/* Data breach simulation */}
          <motion.div
            className="absolute h-4 w-4 rounded-full bg-red-500 right-1/3 top-1/3"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ 
              scale: [0, 1.5, 0],
              opacity: [0, 1, 0]
            }}
            transition={{
              repeat: Infinity,
              duration: 4,
              delay: 2
            }}
          />
          
          {/* Shield protection animation */}
          <motion.div
            className="absolute h-5 w-5 left-1/3 bottom-1/3 text-isimbi-purple"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ 
              scale: [0, 1, 0],
              opacity: [0, 1, 0]
            }}
            transition={{
              repeat: Infinity,
              duration: 3,
              delay: 1.5
            }}
          >
            <Shield />
          </motion.div>
        </motion.div>
      </section>

      {/* Trusted By Section */}
      <section className="py-12 bg-isimbi-navy/50 backdrop-blur-md">
        <div className="container mx-auto px-4">
          <div className="text-center mb-8">
            <p className="text-sm text-gray-400 uppercase tracking-wide">Trusted by industry leaders</p>
          </div>
          <div className="flex flex-wrap justify-center items-center gap-8 md:gap-16">
            {/* Logos in gray/white */}
            <div className="opacity-50 hover:opacity-80 transition-opacity">
              <svg className="h-8 w-auto" viewBox="0 0 100 30" fill="currentColor">
                <rect width="80" height="10" x="10" y="10" rx="2" fill="white" />
                <circle cx="20" cy="15" r="5" fill="currentColor" />
              </svg>
            </div>
            <div className="opacity-50 hover:opacity-80 transition-opacity">
              <svg className="h-8 w-auto" viewBox="0 0 100 30" fill="currentColor">
                <circle cx="50" cy="15" r="15" fill="white" />
                <rect width="20" height="20" x="40" y="5" fill="currentColor" />
              </svg>
            </div>
            <div className="opacity-50 hover:opacity-80 transition-opacity">
              <svg className="h-8 w-auto" viewBox="0 0 100 30" fill="currentColor">
                <path d="M20,5 L80,5 L50,25 Z" fill="white" />
              </svg>
            </div>
            <div className="opacity-50 hover:opacity-80 transition-opacity">
              <svg className="h-8 w-auto" viewBox="0 0 100 30" fill="currentColor">
                <rect width="70" height="20" x="15" y="5" rx="10" fill="white" />
              </svg>
            </div>
            <div className="opacity-50 hover:opacity-80 transition-opacity">
              <svg className="h-8 w-auto" viewBox="0 0 100 30" fill="currentColor">
                <circle cx="30" cy="15" r="10" fill="white" />
                <circle cx="70" cy="15" r="10" fill="white" />
              </svg>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24 bg-gradient-to-b from-isimbi-dark-charcoal to-isimbi-navy">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <Badge variant="outline" className="mb-4 px-3 py-1 text-isimbi-bright-blue border-isimbi-bright-blue/30">
              Features
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">Enterprise-Grade Security Features</h2>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Our comprehensive cybersecurity platform combines AI, machine learning, and expert systems for advanced threat detection and response.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Feature 1 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <Shield size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">Real-Time Threat Detection</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Advanced algorithms constantly monitor for anomalies and potential security breaches, alerting you instantly to critical issues.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Machine learning anomaly detection
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Zero-day exploit protection
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>

            {/* Feature 2 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <Cpu size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">AI-Powered Analysis</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Machine learning models that adapt to your organization's network patterns and behaviors for superior detection.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Behavioral analysis engine
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Predictive threat intelligence
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>

            {/* Feature 3 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <Database size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">Comprehensive Logging</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Full-spectrum data collection and storage with intelligent searching and filtering for forensic analysis.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Encrypted audit trails
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Tamper-proof records
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>

            {/* Feature 4 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <Globe size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">Global Threat Intelligence</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Up-to-date information on emerging threats and attack vectors from around the world.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Real-time threat feeds
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Collaborative defense network
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>
            
            {/* Feature 5 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <Network size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">Network Traffic Analysis</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Deep packet inspection and traffic pattern analysis to identify suspicious network activity.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Protocol anomaly detection
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Encrypted traffic analysis
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>
            
            {/* Feature 6 */}
            <Card className="glass-card relative overflow-hidden group border-isimbi-purple/10">
              <CardHeader className="relative z-10">
                <div className="mb-4 text-isimbi-bright-blue p-2 rounded-md bg-isimbi-bright-blue/10 w-fit">
                  <AlertTriangle size={24} />
                </div>
                <CardTitle className="text-xl font-semibold text-white">Incident Response</CardTitle>
              </CardHeader>
              <CardContent className="relative z-10">
                <p className="text-gray-300 text-sm">
                  Automated and guided incident response workflows to minimize breach impact and recovery time.
                </p>
                <ul className="mt-4 space-y-2">
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Automated containment
                  </li>
                  <li className="flex items-center text-sm text-gray-300">
                    <div className="mr-2 w-1.5 h-1.5 bg-isimbi-bright-blue rounded-full"></div>
                    Forensic analysis tools
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="group p-0 h-auto text-isimbi-bright-blue hover:text-isimbi-bright-blue/80">
                  <span>Learn more</span>
                  <ArrowRight size={16} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </Button>
              </CardFooter>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </Card>
          </div>
        </div>
      </section>
      
      {/* About Section */}
      <section id="about" className="py-24 bg-isimbi-navy relative overflow-hidden">
        <div className="container mx-auto px-4 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <Badge variant="outline" className="mb-4 px-3 py-1 text-isimbi-purple border-isimbi-purple/30">
                About Us
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">Protecting Enterprises in the Digital Age</h2>
              <p className="text-gray-300 mb-6">
                ISIMBI was founded by cybersecurity experts with over 50 years of combined experience protecting critical infrastructure and Fortune 500 companies.
              </p>
              <p className="text-gray-300 mb-6">
                Our mission is to make advanced cybersecurity accessible, intuitive, and effective for organizations of all sizes, combining cutting-edge AI with human expertise.
              </p>
              <div className="grid grid-cols-2 gap-4 mt-8">
                <div className="glass-card p-4 text-center">
                  <div className="text-3xl font-bold text-isimbi-bright-blue mb-1">500+</div>
                  <div className="text-sm text-gray-300">Enterprise Clients</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-3xl font-bold text-isimbi-bright-blue mb-1">99.9%</div>
                  <div className="text-sm text-gray-300">Threat Detection</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-3xl font-bold text-isimbi-bright-blue mb-1">24/7</div>
                  <div className="text-sm text-gray-300">Security Operations</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-3xl font-bold text-isimbi-bright-blue mb-1">15M+</div>
                  <div className="text-sm text-gray-300">Threats Blocked</div>
                </div>
              </div>
            </div>
            <div className="relative">
              <div className="glass-card p-8 border border-isimbi-purple/20 relative z-10">
                <h3 className="text-xl font-semibold text-white mb-4">How ISIMBI Differs</h3>
                <ul className="space-y-4">
                  <li className="flex">
                    <div className="mr-4 h-6 w-6 rounded-full bg-isimbi-bright-blue/20 flex items-center justify-center">
                      <Check className="h-4 w-4 text-isimbi-bright-blue" />
                    </div>
                    <div>
                      <p className="font-medium text-white">AI-First Approach</p>
                      <p className="text-sm text-gray-300">Our solutions are built on advanced neural networks that learn and adapt to your environment.</p>
                    </div>
                  </li>
                  <li className="flex">
                    <div className="mr-4 h-6 w-6 rounded-full bg-isimbi-bright-blue/20 flex items-center justify-center">
                      <Check className="h-4 w-4 text-isimbi-bright-blue" />
                    </div>
                    <div>
                      <p className="font-medium text-white">Behavioral Analysis</p>
                      <p className="text-sm text-gray-300">We analyze patterns and behaviors, not just signatures, to catch zero-day threats.</p>
                    </div>
                  </li>
                  <li className="flex">
                    <div className="mr-4 h-6 w-6 rounded-full bg-isimbi-bright-blue/20 flex items-center justify-center">
                      <Check className="h-4 w-4 text-isimbi-bright-blue" />
                    </div>
                    <div>
                      <p className="font-medium text-white">Seamless Integration</p>
                      <p className="text-sm text-gray-300">Works with your existing security stack without disrupting operations.</p>
                    </div>
                  </li>
                  <li className="flex">
                    <div className="mr-4 h-6 w-6 rounded-full bg-isimbi-bright-blue/20 flex items-center justify-center">
                      <Check className="h-4 w-4 text-isimbi-bright-blue" />
                    </div>
                    <div>
                      <p className="font-medium text-white">Expert Support</p>
                      <p className="text-sm text-gray-300">24/7 access to our security operations team for guided incident response.</p>
                    </div>
                  </li>
                </ul>
              </div>
              
              {/* Decorative elements */}
              <div className="absolute top-1/2 -right-6 transform -translate-y-1/2 w-12 h-12 bg-isimbi-purple/30 rounded-full blur-xl"></div>
              <div className="absolute -bottom-6 left-1/3 w-16 h-16 bg-isimbi-bright-blue/20 rounded-full blur-xl"></div>
            </div>
          </div>
        </div>
        
        {/* Background decorative elements */}
        <div className="absolute top-20 left-0 w-72 h-72 bg-isimbi-purple/5 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 right-0 w-80 h-80 bg-isimbi-bright-blue/5 rounded-full blur-3xl"></div>
      </section>

      {/* Security Section */}
      <section id="security" className="py-24 bg-gradient-to-b from-isimbi-navy to-isimbi-dark-charcoal">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <Badge variant="outline" className="mb-4 px-3 py-1 text-isimbi-bright-blue border-isimbi-bright-blue/30">
              Security
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">Multi-Layered Defense Strategy</h2>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Our platform implements defense-in-depth with multiple security layers working together to protect your assets.
            </p>
          </div>
          
          <div className="relative mx-auto max-w-4xl">
            {/* Layered security visualization */}
            <div className="relative h-96 flex items-center justify-center">
              {/* Outer ring */}
              <div className="absolute w-[500px] h-[500px] border border-dashed border-isimbi-purple/20 rounded-full flex items-center justify-center animate-slow-spin">
                <div className="absolute -top-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-purple text-sm">
                  Network Perimeter
                </div>
                <div className="absolute top-1/4 right-0 transform translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-purple text-sm">
                  Firewall
                </div>
                <div className="absolute -bottom-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-purple text-sm">
                  Intrusion Prevention
                </div>
                <div className="absolute top-1/4 left-0 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-purple text-sm">
                  Traffic Filtering
                </div>
              </div>
              
              {/* Middle ring */}
              <div className="absolute w-[350px] h-[350px] border border-dashed border-isimbi-bright-blue/30 rounded-full flex items-center justify-center animate-slow-spin-reverse">
                <div className="absolute -top-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-bright-blue text-sm">
                  Network Monitoring
                </div>
                <div className="absolute top-1/4 right-0 transform translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-bright-blue text-sm">
                  Behavioral Analysis
                </div>
                <div className="absolute -bottom-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-bright-blue text-sm">
                  Threat Intelligence
                </div>
                <div className="absolute top-1/4 left-0 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-isimbi-bright-blue text-sm">
                  Access Control
                </div>
              </div>
              
              {/* Inner ring */}
              <div className="absolute w-[200px] h-[200px] border border-dashed border-white/30 rounded-full flex items-center justify-center">
                <div className="absolute -top-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-white text-sm">
                  Data Protection
                </div>
                <div className="absolute top-1/4 right-0 transform translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-white text-sm">
                  Encryption
                </div>
                <div className="absolute -bottom-3 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-white text-sm">
                  Authentication
                </div>
                <div className="absolute top-1/4 left-0 transform -translate-x-1/2 bg-isimbi-dark-charcoal px-3 py-1 text-white text-sm">
                  Backup
                </div>
              </div>
              
              {/* Core */}
              <div className="absolute w-24 h-24 rounded-full bg-gradient-to-r from-isimbi-purple to-isimbi-bright-blue flex items-center justify-center">
                <Shield className="h-8 w-8 text-white" />
              </div>
              
              {/* Attack simulation - moving dots */}
              {[...Array(5)].map((_, i) => (
                <motion.div
                  key={i}
                  className="absolute w-3 h-3 rounded-full bg-red-500"
                  initial={{ 
                    x: 300 * Math.cos(i * Math.PI / 2.5),
                    y: 300 * Math.sin(i * Math.PI / 2.5),
                    opacity: 1,
                    scale: 1
                  }}
                  animate={{ 
                    x: 0,
                    y: 0,
                    opacity: 0,
                    scale: 0.5
                  }}
                  transition={{ 
                    repeat: Infinity,
                    repeatType: 'loop',
                    duration: 3 + i,
                    repeatDelay: i * 2,
                    ease: 'easeInOut'
                  }}
                />
              ))}
              
              {/* Defense simulation - pulsing rings */}
              <div className="absolute w-32 h-32 rounded-full border border-isimbi-purple/30 animate-ping" style={{ animationDuration: '3s' }}></div>
              <div className="absolute w-32 h-32 rounded-full border border-isimbi-bright-blue/20 animate-ping" style={{ animationDuration: '4s', animationDelay: '1s' }}></div>
            </div>
          </div>
        </div>
      </section>
      
      {/* CTA Section */}
      <section className="py-24 bg-isimbi-navy relative overflow-hidden">
        <div className="container mx-auto px-4 relative z-10">
          <div className="max-w-3xl mx-auto text-center">
            <Badge variant="outline" className="mb-6 px-3 py-1 text-isimbi-purple border-isimbi-purple/30 inline-block">
              Get Started
            </Badge>
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">Ready to Strengthen Your Security Posture?</h2>
            <p className="text-xl text-gray-300 mb-10">
              Join industry leaders who trust ISIMBI for their most critical security operations.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
              <Link to="/dashboard">
                <Button size="lg" className="bg-isimbi-purple hover:bg-isimbi-purple/90 text-white px-8 shadow-lg shadow-isimbi-purple/20">
                  Experience the Dashboard
                </Button>
              </Link>
              <Button variant="outline" size="lg" className="border-gray-600 text-white hover:bg-white/5">
                Schedule Demo
              </Button>
            </div>
            
            <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="glass-card p-6 text-center">
                <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-isimbi-purple/10">
                  <Monitor className="h-6 w-6 text-isimbi-purple" />
                </div>
                <h3 className="text-lg font-semibold text-white">Live Demo</h3>
                <p className="text-gray-300 text-sm mt-2">
                  See ISIMBI in action with a personalized demo for your team
                </p>
              </div>
              
              <div className="glass-card p-6 text-center">
                <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-isimbi-purple/10">
                  <Shield className="h-6 w-6 text-isimbi-purple" />
                </div>
                <h3 className="text-lg font-semibold text-white">Free Assessment</h3>
                <p className="text-gray-300 text-sm mt-2">
                  Get a complimentary security assessment for your organization
                </p>
              </div>
              
              <div className="glass-card p-6 text-center">
                <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full bg-isimbi-purple/10">
                  <Activity className="h-6 w-6 text-isimbi-purple" />
                </div>
                <h3 className="text-lg font-semibold text-white">Technical Support</h3>
                <p className="text-gray-300 text-sm mt-2">
                  24/7 expert support for all your security questions
                </p>
              </div>
            </div>
          </div>
        </div>
        
        {/* Background decorative elements */}
        <div className="absolute top-0 left-0 w-full h-full">
          <div className="absolute top-10 left-10 w-72 h-72 bg-isimbi-purple/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-10 right-10 w-80 h-80 bg-isimbi-bright-blue/5 rounded-full blur-3xl"></div>
        </div>
      </section>
      
      {/* Contact Section */}
      <section id="contact" className="py-24 bg-isimbi-dark-charcoal">
        <div className="container mx-auto px-4">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-12">
              <Badge variant="outline" className="mb-4 px-3 py-1 text-isimbi-bright-blue border-isimbi-bright-blue/30">
                Contact Us
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">Get in Touch</h2>
              <p className="text-gray-300 max-w-2xl mx-auto">
                Have questions or ready to enhance your cybersecurity? Our team of experts is here to help.
              </p>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
              <div className="lg:col-span-2 space-y-6">
                <div className="glass-card p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Contact Information</h3>
                  <div className="space-y-4">
                    <div className="flex items-start">
                      <div className="mr-3 mt-1">
                        <Globe className="h-5 w-5 text-isimbi-purple" />
                      </div>
                      <div>
                        <p className="text-white font-medium">Global Headquarters</p>
                        <p className="text-gray-300 text-sm">1100 Cyber Avenue, Suite 500<br />San Francisco, CA 94105</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="mr-3 mt-1">
                        <Network className="h-5 w-5 text-isimbi-purple" />
                      </div>
                      <div>
                        <p className="text-white font-medium">International Offices</p>
                        <p className="text-gray-300 text-sm">London • Singapore • Sydney • Tokyo</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="mr-3 mt-1">
                        <Shield className="h-5 w-5 text-isimbi-purple" />
                      </div>
                      <div>
                        <p className="text-white font-medium">Security Operations</p>
                        <p className="text-gray-300 text-sm">24/7 Support: +1 (800) 555-ISIMBI</p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-6 pt-6 border-t border-gray-700">
                    <h4 className="text-white font-medium mb-3">Follow Us</h4>
                    <div className="flex space-x-4">
                      <div className="h-10 w-10 rounded-full bg-white/10 flex items-center justify-center hover:bg-white/20 transition-colors">
                        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="text-white"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"></path></svg>
                      </div>
                      <div className="h-10 w-10 rounded-full bg-white/10 flex items-center justify-center hover:bg-white/20 transition-colors">
                        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="text-white"><path d="M23 3a10.9 10.9 0 0 1-3.14 1.53 4.48 4.48 0 0 0-7.86 3v1A10.66 10.66 0 0 1 3 4s-4 9 5 13a11.64 11.64 0 0 1-7 2c9 5 20 0 20-11.5a4.5 4.5 0 0 0-.08-.83A7.72 7.72 0 0 0 23 3z"></path></svg>
                      </div>
                      <div className="h-10 w-10 rounded-full bg-white/10 flex items-center justify-center hover:bg-white/20 transition-colors">
                        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="text-white"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"></rect><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"></path><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"></line></svg>
                      </div>
                      <div className="h-10 w-10 rounded-full bg-white/10 flex items-center justify-center hover:bg-white/20 transition-colors">
                        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" className="text-white"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path><rect x="2" y="9" width="4" height="12"></rect><circle cx="4" cy="4" r="2"></circle></svg>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="lg:col-span-3">
                <div className="glass-card p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Send Us a Message</h3>
                  <form className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Your Name</label>
                        <input 
                          type="text" 
                          className="w-full px-4 py-2 bg-white/5 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-isimbi-purple/50 focus:border-transparent" 
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Email Address</label>
                        <input 
                          type="email" 
                          className="w-full px-4 py-2 bg-white/5 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-isimbi-purple/50 focus:border-transparent" 
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-1">Company</label>
                      <input 
                        type="text" 
                        className="w-full px-4 py-2 bg-white/5 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-isimbi-purple/50 focus:border-transparent" 
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-1">Message</label>
                      <textarea 
                        rows={4} 
                        className="w-full px-4 py-2 bg-white/5 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-isimbi-purple/50 focus:border-transparent" 
                      ></textarea>
                    </div>
                    <div>
                      <Button className="w-full bg-isimbi-purple hover:bg-isimbi-purple/90 text-white">
                        Submit Message
                      </Button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-isimbi-dark-charcoal py-10 border-t border-white/10">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
            <div className="md:col-span-3">
              <div className="flex items-center mb-4">
                <div className="h-10 w-10 rounded-md bg-isimbi-purple flex items-center justify-center">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <span className="text-2xl font-bold text-white ml-2 tracking-wider">ISIMBI</span>
              </div>
              <p className="text-sm text-gray-400">
                Advanced cybersecurity solutions for modern enterprises, combining AI, machine learning, and expert systems for superior protection.
              </p>
            </div>
            
            <div className="md:col-span-2">
              <h3 className="font-semibold text-white mb-4">Products</h3>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">ISIMBI Sentinel</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Network Guardian</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Endpoint Shield</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Cloud Protector</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Threat Intelligence</a></li>
              </ul>
            </div>
            
            <div className="md:col-span-2">
              <h3 className="font-semibold text-white mb-4">Resources</h3>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Documentation</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">API Reference</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Blog</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Case Studies</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Resource Library</a></li>
              </ul>
            </div>
            
            <div className="md:col-span-2">
              <h3 className="font-semibold text-white mb-4">Company</h3>
              <ul className="space-y-2 text-sm">
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">About Us</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Careers</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Partners</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Press</a></li>
                <li><a href="#" className="text-gray-400 hover:text-isimbi-purple">Contact</a></li>
              </ul>
            </div>
            
            <div className="md:col-span-3">
              <h3 className="font-semibold text-white mb-4">Stay Updated</h3>
              <p className="text-sm text-gray-400 mb-4">
                Subscribe to our newsletter for security alerts and updates.
              </p>
              <div className="flex">
                <input 
                  type="email" 
                  placeholder="Your email" 
                  className="bg-white/5 border border-gray-700 px-3 py-2 rounded-l-md text-white text-sm flex-1 focus:outline-none focus:ring-1 focus:ring-isimbi-purple"
                />
                <button className="bg-isimbi-purple hover:bg-isimbi-purple/90 px-3 py-2 text-white rounded-r-md">
                  Subscribe
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-2">
                We respect your privacy. Unsubscribe at any time.
              </p>
            </div>
          </div>
          
          <div className="pt-8 mt-8 border-t border-gray-800 flex flex-col md:flex-row justify-between items-center">
            <div className="text-sm text-gray-500 mb-4 md:mb-0">
              &copy; {new Date().getFullYear()} ISIMBI Security. All rights reserved.
            </div>
            <div className="flex space-x-6">
              <a href="#" className="text-gray-400 hover:text-isimbi-purple text-sm">Privacy Policy</a>
              <a href="#" className="text-gray-400 hover:text-isimbi-purple text-sm">Terms of Service</a>
              <a href="#" className="text-gray-400 hover:text-isimbi-purple text-sm">Cookie Policy</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
