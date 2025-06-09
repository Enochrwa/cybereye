import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { 
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, ChevronDown, ChevronUp,
  Clock, Cpu, Database, Download, FileDown, Filter, Globe, HardDrive, Info,
  Laptop, Monitor, Network, Power, RefreshCcw, Server, Settings, Shield, Terminal,
  Wifi, X, Check, Maximize, Bell, Zap, UsersIcon, Search
} from "lucide-react";

// Import sub-components
import NetworkConnectionsPanel from './NetworkConnectionsPanel';
import DeviceAccessMonitor from './DeviceAccessMonitor';
import AuthenticationMonitor from './AuthenticationMonitor';
import UserBehaviorAnalysis from './UserBehaviorAnalysis';
import ThreatIndicatorsPanel from './ThreatIndicatorsPanel';

// Types for system stats
interface SystemStats {
  hostname: string;
  osType: string;
  uptime: number;
  cpuModel: string;
  totalRAM: number;
  systemHealth: 'Healthy' | 'Degraded' | 'Overloaded';
}

// Types for system metrics
interface SystemMetric {
  timestamp: Date;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  temperature: number;
}

// Types for system events
interface SystemEvent {
  id: string;
  timestamp: Date;
  type: 'info' | 'warning' | 'critical';
  message: string;
  details?: string;
  source: string;
  category: 'system' | 'file' | 'network' | 'login' | 'usb';
}

// Types for process data
interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  user: string;
  status: 'running' | 'sleeping' | 'stopped' | 'zombie';
  suspicious: boolean;
}

// Types for network connection
interface NetworkConnection {
  id: string;
  localIP: string;
  remoteIP: string;
  port: number;
  protocol: string;
  state: string;
  process: string;
  country?: string;
  city?: string;
}

const LiveSystemMonitor = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('overview');
  const [expanded, setExpanded] = useState(true);
  const [metrics, setMetrics] = useState<SystemMetric[]>([]);
  const [events, setEvents] = useState<SystemEvent[]>([]);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [currentCPU, setCurrentCPU] = useState(0);
  const [currentMemory, setCurrentMemory] = useState(0);
  const [currentDisk, setCurrentDisk] = useState(0);
  const [currentNetwork, setCurrentNetwork] = useState(0);
  const [currentTemperature, setCurrentTemperature] = useState(0);
  const [systemStats, setSystemStats] = useState<SystemStats>({
    hostname: 'server-prod-01',
    osType: 'Linux (Ubuntu 22.04 LTS)',
    uptime: 184320, // in seconds (2 days, 3 hours)
    cpuModel: 'Intel Xeon E5-2680 v4 @ 2.40GHz',
    totalRAM: 32, // GB
    systemHealth: 'Healthy'
  });
  const [timeRange, setTimeRange] = useState('5min');
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [alertSounds, setAlertSounds] = useState(false);
  const [autoResponse, setAutoResponse] = useState(true);

  // Generate sample metrics for simulation
  const generateMetrics = () => {
    const now = new Date();
    let cpu = Math.floor(Math.random() * 40) + 10; // 10-50% CPU usage
    let memory = Math.floor(Math.random() * 30) + 40; // 40-70% memory usage
    const disk = Math.floor(Math.random() * 20) + 30; // 30-50% disk usage
    const network = Math.floor(Math.random() * 60) + 20; // 20-80% network usage
    const temperature = Math.floor(Math.random() * 15) + 45; // 45-60°C
    
    // Occasionally generate spikes
    if (Math.random() > 0.9) {
      cpu += 30; // CPU spike
      if (cpu > 100) cpu = 100;
    }
    
    if (Math.random() > 0.95) {
      memory += 20; // Memory spike
      if (memory > 100) memory = 100;
    }
    
    return {
      timestamp: now,
      cpu,
      memory,
      disk,
      network,
      temperature
    };
  };
  
  // Generate a system event based on metrics
  const generateEvent = (currentMetrics: SystemMetric): SystemEvent | null => {
    // Check for high CPU
    if (currentMetrics.cpu > 80) {
      return {
        id: `event-${Date.now()}-cpu`,
        timestamp: new Date(),
        type: currentMetrics.cpu > 90 ? 'critical' : 'warning',
        message: `High CPU Usage: ${currentMetrics.cpu}%`,
        details: 'System experiencing unusually high CPU load',
        source: 'CPU Monitor',
        category: 'system'
      };
    }
    
    // Check for high memory
    if (currentMetrics.memory > 85) {
      return {
        id: `event-${Date.now()}-memory`,
        timestamp: new Date(),
        type: currentMetrics.memory > 95 ? 'critical' : 'warning',
        message: `Low Memory: ${100 - currentMetrics.memory}% Free`,
        details: 'System memory resources are running low',
        source: 'Memory Monitor',
        category: 'system'
      };
    }
    
    // Random events occasionally
    if (Math.random() > 0.9) {
      const events = [
        {
          type: 'info',
          message: 'System update available',
          details: 'New security patches are available for installation',
          source: 'Update Service',
          category: 'system'
        },
        {
          type: 'warning',
          message: 'Network anomaly detected',
          details: 'Unusual outbound connection pattern detected',
          source: 'Network Monitor',
          category: 'network'
        },
        {
          type: 'info',
          message: 'Backup completed',
          details: 'Scheduled system backup completed successfully',
          source: 'Backup Service',
          category: 'system'
        },
        {
          type: 'warning',
          message: 'Failed login attempt',
          details: 'Multiple failed login attempts from IP 192.168.1.45',
          source: 'Auth Monitor',
          category: 'login'
        },
        {
          type: 'info',
          message: 'USB device connected',
          details: 'Kingston DataTraveler USB drive mounted at /media/usb0',
          source: 'Device Monitor',
          category: 'usb'
        }
      ];
      
      const randomEvent = events[Math.floor(Math.random() * events.length)];
      return {
        id: `event-${Date.now()}-random`,
        timestamp: new Date(),
        type: randomEvent.type as 'info' | 'warning' | 'critical',
        message: randomEvent.message,
        details: randomEvent.details,
        source: randomEvent.source,
        category: randomEvent.category as 'system' | 'file' | 'network' | 'login' | 'usb'
      };
    }
    
    return null;
  };
  
  // Generate sample processes
  const generateProcesses = () => {
    const processList: ProcessInfo[] = [
      {
        pid: 1,
        name: 'systemd',
        cpu: Math.floor(Math.random() * 5),
        memory: Math.floor(Math.random() * 2) + 1,
        disk: 0,
        network: 0,
        user: 'root',
        status: 'running',
        suspicious: false
      },
      {
        pid: 432,
        name: 'sshd',
        cpu: Math.floor(Math.random() * 2),
        memory: Math.floor(Math.random() * 1) + 0.5,
        disk: 0,
        network: Math.floor(Math.random() * 2),
        user: 'root',
        status: 'running',
        suspicious: false
      },
      {
        pid: 845,
        name: 'nginx',
        cpu: Math.floor(Math.random() * 10) + 5,
        memory: Math.floor(Math.random() * 5) + 3,
        disk: Math.floor(Math.random() * 1),
        network: Math.floor(Math.random() * 20) + 10,
        user: 'www-data',
        status: 'running',
        suspicious: false
      },
      {
        pid: 1289,
        name: 'mysql',
        cpu: Math.floor(Math.random() * 15) + 5,
        memory: Math.floor(Math.random() * 20) + 10,
        disk: Math.floor(Math.random() * 10) + 5,
        network: Math.floor(Math.random() * 5),
        user: 'mysql',
        status: 'running',
        suspicious: false
      },
      {
        pid: 2567,
        name: 'java',
        cpu: Math.floor(Math.random() * 25) + 15,
        memory: Math.floor(Math.random() * 30) + 15,
        disk: Math.floor(Math.random() * 5),
        network: Math.floor(Math.random() * 10),
        user: 'tomcat',
        status: 'running',
        suspicious: false
      },
      {
        pid: 3421,
        name: 'python3',
        cpu: Math.floor(Math.random() * 10) + 2,
        memory: Math.floor(Math.random() * 8) + 2,
        disk: Math.floor(Math.random() * 3),
        network: Math.floor(Math.random() * 5),
        user: 'www-data',
        status: 'running',
        suspicious: false
      },
      {
        pid: 4532,
        name: 'node',
        cpu: Math.floor(Math.random() * 12) + 3,
        memory: Math.floor(Math.random() * 15) + 5,
        disk: Math.floor(Math.random() * 2),
        network: Math.floor(Math.random() * 8) + 2,
        user: 'nodejs',
        status: 'running',
        suspicious: false
      },
    ];
    
    // Occasionally add a suspicious process (10% chance)
    if (Math.random() > 0.9) {
      const suspiciousProcesses = [
        {
          name: 'crypto_miner',
          cpu: Math.floor(Math.random() * 40) + 60,
          memory: Math.floor(Math.random() * 10) + 5,
          user: 'unknown'
        },
        {
          name: 'backdoor.sh',
          cpu: Math.floor(Math.random() * 5) + 1,
          memory: Math.floor(Math.random() * 2) + 1,
          user: 'root'
        },
        {
          name: 'data_exfil.py',
          cpu: Math.floor(Math.random() * 10) + 5,
          memory: Math.floor(Math.random() * 5) + 2,
          user: 'www-data'
        }
      ];
      
      const randomSuspicious = suspiciousProcesses[Math.floor(Math.random() * suspiciousProcesses.length)];
      
      processList.push({
        pid: 9000 + Math.floor(Math.random() * 1000),
        name: randomSuspicious.name,
        cpu: randomSuspicious.cpu,
        memory: randomSuspicious.memory,
        disk: Math.floor(Math.random() * 5),
        network: Math.floor(Math.random() * 30) + 10,
        user: randomSuspicious.user,
        status: 'running',
        suspicious: true
      });
      
      // Create an event for the suspicious process
      const newEvent: SystemEvent = {
        id: `event-${Date.now()}-suspicious`,
        timestamp: new Date(),
        type: 'critical',
        message: `Suspicious Process Detected: ${randomSuspicious.name}`,
        details: `Process running as ${randomSuspicious.user} with high resource usage`,
        source: 'Process Monitor',
        category: 'system'
      };
      
      setEvents(prev => [newEvent, ...prev]);
      
      toast({
        title: "Suspicious Process Detected",
        description: `Process ${randomSuspicious.name} is showing unusual behavior`,
        variant: "destructive"
      });
      
      // Update system health if suspicious process is detected
      if (randomSuspicious.cpu > 60) {
        setSystemStats(prev => ({
          ...prev,
          systemHealth: 'Degraded'
        }));
      }
    }
    
    return processList;
  };
  
  // Format time for display
  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    return `${days}d ${hours}h ${minutes}m`;
  };
  
  // Format bytes for display
  const formatBytes = (bytes: number, decimals = 2): string => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };
  
  // Simulate real-time monitoring
  useEffect(() => {
    if (!isMonitoring) return;
    
    const interval = setInterval(() => {
      // Generate new metrics
      const newMetrics = generateMetrics();
      
      // Update current values
      setCurrentCPU(newMetrics.cpu);
      setCurrentMemory(newMetrics.memory);
      setCurrentDisk(newMetrics.disk);
      setCurrentNetwork(newMetrics.network);
      setCurrentTemperature(newMetrics.temperature);
      
      // Update uptime
      setSystemStats(prev => ({
        ...prev,
        uptime: prev.uptime + 5
      }));
      
      // Update metrics history (keep last 20 points)
      setMetrics(prev => {
        const updated = [...prev, newMetrics];
        return updated.slice(-20);
      });
      
      // Check if we should generate an event
      const newEvent = generateEvent(newMetrics);
      if (newEvent) {
        setEvents(prev => [newEvent, ...prev].slice(0, 100));
        
        // Show toast for critical events
        if (newEvent.type === 'critical') {
          toast({
            title: "Critical System Event",
            description: newEvent.message,
            variant: "destructive"
          });
          
          // Play alert sound if enabled
          if (alertSounds) {
            // Here we would trigger alert sound
            console.log("Alert sound would play here");
          }
        }
      }
      
      // Update processes occasionally
      if (Math.random() > 0.7) {
        setProcesses(generateProcesses());
      }
      
    }, 3000);
    
    return () => clearInterval(interval);
  }, [toast, isMonitoring, alertSounds]);
  
  // Get color for metric based on value
  const getMetricColor = (value: number) => {
    if (value < 60) return 'text-green-500';
    if (value < 80) return 'text-amber-500';
    return 'text-red-500';
  };
  
  // Format event type badge
  const getEventTypeBadge = (type: 'info' | 'warning' | 'critical') => {
    switch (type) {
      case 'critical':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Critical</Badge>;
      case 'warning':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Warning</Badge>;
      case 'info':
        return <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500">Info</Badge>;
    }
  };
  
  // Get category icon for events
  const getEventCategoryIcon = (category: string) => {
    switch (category) {
      case 'system':
        return <Server className="h-4 w-4" />;
      case 'file':
        return <FileDown className="h-4 w-4" />;
      case 'network':
        return <Globe className="h-4 w-4" />;
      case 'login':
        return <UsersIcon className="h-4 w-4" />;
      case 'usb':
        return <Laptop className="h-4 w-4" />;
      default:
        return <Info className="h-4 w-4" />;
    }
  };
  
  // Get health badge
  const getHealthBadge = (status: string) => {
    switch (status) {
      case 'Healthy':
        return <Badge className="bg-green-500 hover:bg-green-600">{status}</Badge>;
      case 'Degraded':
        return <Badge className="bg-amber-500 hover:bg-amber-600">{status}</Badge>;
      case 'Overloaded':
        return <Badge variant="destructive">{status}</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };
  
  // Export logs as JSON
  const exportLogs = (format: 'json' | 'csv' | 'pdf') => {
    const data = JSON.stringify(events, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `system-events-${new Date().toISOString()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    toast({
      title: "Export Complete",
      description: `Logs exported as ${format.toUpperCase()}`,
    });
  };
  
  // Run manual scan
  const runManualScan = () => {
    toast({
      title: "Scan Initiated",
      description: "System scan in progress...",
    });
    
    // Simulate scan completion
    setTimeout(() => {
      toast({
        title: "Scan Complete",
        description: "No threats detected in system scan",
      });
    }, 3000);
  };
  
  // Optimize system
  const optimizeSystem = () => {
    toast({
      title: "System Optimization",
      description: "Optimization routine started...",
    });
    
    // Simulate optimization completion
    setTimeout(() => {
      setCurrentCPU(prev => Math.max(prev - 15, 5));
      setCurrentMemory(prev => Math.max(prev - 20, 10));
      
      toast({
        title: "Optimization Complete",
        description: "System resources optimized successfully",
      });
    }, 2500);
  };
  
  // Toggle monitoring
  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring);
    toast({
      title: isMonitoring ? "Monitoring Paused" : "Monitoring Resumed",
      description: isMonitoring ? 
        "Real-time updates have been paused" : 
        "Real-time updates have been resumed",
    });
  };
  
  // Sort processes by CPU usage
  const sortedProcesses = [...processes].sort((a, b) => b.cpu - a.cpu);

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="p-4 border-b border-border flex flex-row justify-between items-center">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5 text-isimbi-purple" />
            Live System Monitoring
          </CardTitle>
          <CardDescription>Real-time monitoring of system metrics and behaviors</CardDescription>
        </div>
        <Button 
          variant="ghost" 
          size="sm" 
          className="h-8 w-8 p-0"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </Button>
      </CardHeader>
      
      {expanded && (
        <>
          <div className="p-4 border-b border-border bg-muted/30">
            <Tabs defaultValue="overview" onValueChange={setActiveTab}>
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="processes">Processes</TabsTrigger>
                <TabsTrigger value="events">Events Log</TabsTrigger>
                <TabsTrigger value="resources">Resource Usage</TabsTrigger>
                <TabsTrigger value="network">Network Connections</TabsTrigger>
                <TabsTrigger value="devices">Device Access</TabsTrigger>
                <TabsTrigger value="authentication">Authentication</TabsTrigger>
                <TabsTrigger value="behavior">User Behavior</TabsTrigger>
                <TabsTrigger value="threats">Threat Indicators</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
          
          <CardContent className="p-0">
            <TabsContent value="overview" className="p-4 mt-0">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* System Info Panel */}
                <div className="border rounded-lg p-4">
                  <h3 className="text-base font-medium mb-4">System Information</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <div>
                        <div className="text-sm text-muted-foreground">Hostname</div>
                        <div className="font-medium">{systemStats.hostname}</div>
                      </div>
                      
                      <div>
                        <div className="text-sm text-muted-foreground">Operating System</div>
                        <div className="font-medium">{systemStats.osType}</div>
                      </div>
                      
                      <div>
                        <div className="text-sm text-muted-foreground">CPU Model</div>
                        <div className="font-medium">{systemStats.cpuModel}</div>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div>
                        <div className="text-sm text-muted-foreground">System Uptime</div>
                        <div className="font-medium">{formatUptime(systemStats.uptime)}</div>
                      </div>
                      
                      <div>
                        <div className="text-sm text-muted-foreground">Total RAM</div>
                        <div className="font-medium">{systemStats.totalRAM} GB</div>
                      </div>
                      
                      <div>
                        <div className="text-sm text-muted-foreground">System Health</div>
                        <div>{getHealthBadge(systemStats.systemHealth)}</div>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Control Panel */}
                <div className="border rounded-lg p-4">
                  <h3 className="text-base font-medium mb-4">Control Panel</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-4">
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={runManualScan}
                      >
                        <Shield className="mr-2 h-4 w-4" />
                        Run Manual Scan
                      </Button>
                      
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={optimizeSystem}
                      >
                        <RefreshCcw className="mr-2 h-4 w-4" />
                        Optimize System
                      </Button>
                      
                      <Button 
                        variant={isMonitoring ? "default" : "outline"} 
                        className="w-full justify-start"
                        onClick={toggleMonitoring}
                      >
                        {isMonitoring ? (
                          <><Power className="mr-2 h-4 w-4" /> Pause Monitoring</>
                        ) : (
                          <><Activity className="mr-2 h-4 w-4" /> Resume Monitoring</>
                        )}
                      </Button>
                      
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={() => exportLogs('json')}
                      >
                        <Download className="mr-2 h-4 w-4" />
                        Download Logs
                      </Button>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Real-time Monitoring</div>
                        <div className="flex items-center">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input 
                              type="checkbox" 
                              checked={isMonitoring} 
                              onChange={() => setIsMonitoring(!isMonitoring)} 
                              className="sr-only peer" 
                            />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                          </label>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Alert Sounds</div>
                        <div className="flex items-center">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input 
                              type="checkbox" 
                              checked={alertSounds} 
                              onChange={() => setAlertSounds(!alertSounds)} 
                              className="sr-only peer" 
                            />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                          </label>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Auto-Response</div>
                        <div className="flex items-center">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input 
                              type="checkbox" 
                              checked={autoResponse} 
                              onChange={() => setAutoResponse(!autoResponse)} 
                              className="sr-only peer" 
                            />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                          </label>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Export Format</div>
                        <div className="flex items-center gap-2">
                          <Button size="sm" variant="outline" onClick={() => exportLogs('json')}>JSON</Button>
                          <Button size="sm" variant="outline" onClick={() => exportLogs('csv')}>CSV</Button>
                          <Button size="sm" variant="outline" onClick={() => exportLogs('pdf')}>PDF</Button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Current Metrics */}
                <div className="border rounded-lg col-span-full">
                  <div className="flex justify-between items-center p-4 border-b">
                    <h3 className="text-base font-medium">Current Resource Utilization</h3>
                    <div className="flex items-center gap-2">
                      <Button variant="ghost" size="sm" className="gap-1">
                        <RefreshCcw className="h-3.5 w-3.5" />
                        Refresh
                      </Button>
                    </div>
                  </div>
                  <div className="p-4">
                    <div className="grid grid-cols-5 gap-4">
                      <div className="border rounded-md p-3">
                        <div className="text-xs text-muted-foreground mb-1">CPU Usage</div>
                        <div className="flex justify-between items-center">
                          <Cpu className="h-4 w-4 text-blue-500" />
                          <div className={`text-xl font-bold ${getMetricColor(currentCPU)}`}>
                            {currentCPU}%
                          </div>
                        </div>
                        <Progress value={currentCPU} className="h-1 mt-2" />
                      </div>
                      
                      <div className="border rounded-md p-3">
                        <div className="text-xs text-muted-foreground mb-1">Memory Usage</div>
                        <div className="flex justify-between items-center">
                          <Database className="h-4 w-4 text-purple-500" />
                          <div className={`text-xl font-bold ${getMetricColor(currentMemory)}`}>
                            {currentMemory}%
                          </div>
                        </div>
                        <Progress value={currentMemory} className="h-1 mt-2" />
                      </div>
                      
                      <div className="border rounded-md p-3">
                        <div className="text-xs text-muted-foreground mb-1">Disk I/O</div>
                        <div className="flex justify-between items-center">
                          <HardDrive className="h-4 w-4 text-green-500" />
                          <div className={`text-xl font-bold ${getMetricColor(currentDisk)}`}>
                            {currentDisk}%
                          </div>
                        </div>
                        <Progress value={currentDisk} className="h-1 mt-2" />
                      </div>
                      
                      <div className="border rounded-md p-3">
                        <div className="text-xs text-muted-foreground mb-1">Network</div>
                        <div className="flex justify-between items-center">
                          <Wifi className="h-4 w-4 text-amber-500" />
                          <div className={`text-xl font-bold ${getMetricColor(currentNetwork)}`}>
                            {currentNetwork}%
                          </div>
                        </div>
                        <Progress value={currentNetwork} className="h-1 mt-2" />
                      </div>
                      
                      <div className="border rounded-md p-3">
                        <div className="text-xs text-muted-foreground mb-1">Temperature</div>
                        <div className="flex justify-between items-center">
                          <Zap className="h-4 w-4 text-red-500" />
                          <div className={`text-xl font-bold ${getMetricColor(currentTemperature)}`}>
                            {currentTemperature}°C
                          </div>
                        </div>
                        <Progress value={currentTemperature} max={100} className="h-1 mt-2" />
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Recent Events */}
                <div className="border rounded-lg">
                  <div className="flex justify-between items-center p-4 border-b">
                    <h3 className="text-base font-medium">Recent System Events</h3>
                    <Button variant="ghost" size="sm" onClick={() => setActiveTab('events')}>View All</Button>
                  </div>
                  <ScrollArea className="h-[250px]">
                    {events.length > 0 ? (
                      <div className="divide-y">
                        {events.slice(0, 5).map((event) => (
                          <div key={event.id} className="p-3 hover:bg-muted/50">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {getEventCategoryIcon(event.category)}
                                <span className="font-medium">{event.message}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                {getEventTypeBadge(event.type)}
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {event.timestamp.toLocaleTimeString()} | Source: {event.source}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-8 text-center text-sm text-muted-foreground">
                        No system events recorded
                      </div>
                    )}
                  </ScrollArea>
                </div>
                
                {/* Top Processes */}
                <div className="border rounded-lg">
                  <div className="flex justify-between items-center p-4 border-b">
                    <h3 className="text-base font-medium">Top Processes</h3>
                    <Button variant="ghost" size="sm" onClick={() => setActiveTab('processes')}>View All</Button>
                  </div>
                  <div className="p-0">
                    <div className="grid grid-cols-6 gap-2 py-2 px-3 bg-muted text-xs font-medium">
                      <div className="col-span-2">Process</div>
                      <div className="col-span-1">User</div>
                      <div className="col-span-1">CPU %</div>
                      <div className="col-span-1">Mem %</div>
                      <div className="col-span-1">Status</div>
                    </div>
                    
                    <ScrollArea className="h-[210px]">
                      <div className="divide-y">
                        {sortedProcesses.slice(0, 5).map((process) => (
                          <div 
                            key={process.pid}
                            className={`grid grid-cols-6 gap-2 py-2 px-3 text-xs ${
                              process.suspicious ? 'bg-red-500/5' : ''
                            } hover:bg-muted/50`}
                          >
                            <div className="col-span-2 flex items-center gap-1">
                              {process.suspicious && <AlertTriangle className="h-3 w-3 text-red-500" />}
                              <span className={process.suspicious ? 'font-medium text-red-500' : ''}>
                                {process.name}
                              </span>
                            </div>
                            <div className="col-span-1">{process.user}</div>
                            <div 
                              className={`col-span-1 ${
                                process.cpu > 50 ? 'text-red-500 font-medium' : 
                                process.cpu > 20 ? 'text-amber-500' : ''
                              }`}
                            >
                              {process.cpu}%
                            </div>
                            <div 
                              className={`col-span-1 ${
                                process.memory > 50 ? 'text-red-500 font-medium' : 
                                process.memory > 20 ? 'text-amber-500' : ''
                              }`}
                            >
                              {process.memory}%
                            </div>
                            <div className="col-span-1">
                              <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                                {process.status}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="processes" className="p-4 mt-0">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-medium">Active Processes ({processes.length})</h3>
                  <div className="flex items-center gap-2">
                    <div className="relative">
                      <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                      <input
                        type="search"
                        placeholder="Search processes..."
                        className="pl-8 h-9 w-[250px] rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                      />
                    </div>
                    <Button size="sm" variant="outline" className="h-9">
                      <Filter className="mr-2 h-4 w-4" />
                      Filter
                    </Button>
                    <Button size="sm" className="h-9">Refresh</Button>
                  </div>
                </div>
                
                <div className="border rounded-lg overflow-hidden">
                  <div className="grid grid-cols-8 gap-2 py-2 px-3 bg-muted text-xs font-medium">
                    <div className="col-span-1">PID</div>
                    <div className="col-span-2">Name</div>
                    <div className="col-span-1">CPU %</div>
                    <div className="col-span-1">Memory %</div>
                    <div className="col-span-1">User</div>
                    <div className="col-span-1">Status</div>
                    <div className="col-span-1">Actions</div>
                  </div>
                  
                  <ScrollArea className="h-[500px]">
                    <div className="divide-y">
                      {sortedProcesses.map((process) => (
                        <div 
                          key={process.pid}
                          className={`grid grid-cols-8 gap-2 py-2 px-3 text-xs ${
                            process.suspicious ? 'bg-red-500/5' : ''
                          } hover:bg-muted/50`}
                        >
                          <div className="col-span-1 font-mono">{process.pid}</div>
                          <div className="col-span-2 flex items-center">
                            {process.suspicious && <AlertTriangle className="h-3 w-3 text-red-500 mr-1" />}
                            <span className={process.suspicious ? 'font-medium text-red-500' : ''}>
                              {process.name}
                            </span>
                          </div>
                          <div 
                            className={`col-span-1 ${
                              process.cpu > 50 ? 'text-red-500 font-medium' : 
                              process.cpu > 20 ? 'text-amber-500' : ''
                            }`}
                          >
                            {process.cpu}%
                          </div>
                          <div 
                            className={`col-span-1 ${
                              process.memory > 50 ? 'text-red-500 font-medium' : 
                              process.memory > 20 ? 'text-amber-500' : ''
                            }`}
                          >
                            {process.memory}%
                          </div>
                          <div className="col-span-1">{process.user}</div>
                          <div className="col-span-1">
                            <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                              {process.status}
                            </Badge>
                          </div>
                          <div className="col-span-1 flex items-center gap-1">
                            <Button 
                              variant={process.suspicious ? "destructive" : "ghost"} 
                              size="sm" 
                              className="h-6 text-[10px]"
                            >
                              {process.suspicious ? "Terminate" : "Details"}
                            </Button>
                            
                            {process.suspicious && (
                              <Button 
                                variant="outline"
                                size="sm" 
                                className="h-6 text-[10px]"
                              >
                                Quarantine
                              </Button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="events" className="p-4 mt-0">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-medium">System Events ({events.length})</h3>
                  <div className="flex items-center gap-2">
                    <div className="flex bg-muted rounded-md p-1">
                      <Button variant="ghost" size="sm" className="h-8 text-xs">All</Button>
                      <Button variant="ghost" size="sm" className="h-8 text-xs">Critical</Button>
                      <Button variant="ghost" size="sm" className="h-8 text-xs">Warning</Button>
                      <Button variant="ghost" size="sm" className="h-8 text-xs">Info</Button>
                    </div>
                    <Button size="sm" variant="outline" onClick={() => exportLogs('json')}>Export</Button>
                  </div>
                </div>
                
                <div className="border rounded-md overflow-hidden">
                  <ScrollArea className="h-[500px]">
                    {events.length > 0 ? (
                      <div className="divide-y">
                        {events.map((event) => (
                          <div 
                            key={event.id} 
                            className={`p-3 hover:bg-muted/50 ${
                              event.type === 'critical' ? 'bg-red-500/5' :
                              event.type === 'warning' ? 'bg-amber-500/5' : ''
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {getEventCategoryIcon(event.category)}
                                <span className="font-medium">{event.message}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                {getEventTypeBadge(event.type)}
                                <span className="text-xs text-muted-foreground">
                                  {event.timestamp.toLocaleTimeString()}
                                </span>
                              </div>
                            </div>
                            <div className="text-sm text-muted-foreground mt-1">
                              {event.details}
                            </div>
                            <div className="text-xs text-muted-foreground mt-2">
                              Source: {event.source}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-8 text-center text-sm text-muted-foreground">
                        No system events recorded
                      </div>
                    )}
                  </ScrollArea>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="resources" className="p-4 mt-0">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium">Resource Usage</h3>
                <div className="flex items-center gap-2">
                  <div className="flex bg-muted rounded-md p-1">
                    <Button variant="ghost" size="sm" className="h-8 text-xs">1 min</Button>
                    <Button variant="ghost" size="sm" className="h-8 text-xs">5 min</Button>
                    <Button variant="ghost" size="sm" className="h-8 text-xs">30 min</Button>
                  </div>
                </div>
              </div>
              
              {/* This would be replaced with actual Plotly graphs */}
              <div className="space-y-4">
                <div className="border rounded-lg p-4">
                  <h4 className="text-sm font-medium mb-2">CPU Usage (System & Per Core)</h4>
                  <div className="bg-muted h-64 rounded-md flex items-center justify-center">
                    <span className="text-muted-foreground">Interactive CPU Usage Graph would appear here</span>
                  </div>
                </div>
                
                <div className="border rounded-lg p-4">
                  <h4 className="text-sm font-medium mb-2">Memory Usage (Total/Used/Free)</h4>
                  <div className="bg-muted h-64 rounded-md flex items-center justify-center">
                    <span className="text-muted-foreground">Interactive Memory Usage Graph would appear here</span>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="border rounded-lg p-4">
                    <h4 className="text-sm font-medium mb-2">Disk I/O (Read/Write MB/s)</h4>
                    <div className="bg-muted h-48 rounded-md flex items-center justify-center">
                      <span className="text-muted-foreground">Interactive Disk I/O Graph would appear here</span>
                    </div>
                  </div>
                  
                  <div className="border rounded-lg p-4">
                    <h4 className="text-sm font-medium mb-2">Network Traffic (Upload/Download)</h4>
                    <div className="bg-muted h-48 rounded-md flex items-center justify-center">
                      <span className="text-muted-foreground">Interactive Network Traffic Graph would appear here</span>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="network" className="p-4 mt-0">
              <NetworkConnectionsPanel />
            </TabsContent>
            
            <TabsContent value="devices" className="p-4 mt-0">
              <DeviceAccessMonitor />
            </TabsContent>
            
            <TabsContent value="authentication" className="p-4 mt-0">
              <AuthenticationMonitor />
            </TabsContent>
            
            <TabsContent value="behavior" className="p-4 mt-0">
              <UserBehaviorAnalysis />
            </TabsContent>
            
            <TabsContent value="threats" className="p-4 mt-0">
              <ThreatIndicatorsPanel />
            </TabsContent>
          </CardContent>
          
          <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between p-4">
            <div className="text-xs text-muted-foreground flex items-center">
              <Clock size={14} className="mr-1" />
              Last updated: {new Date().toLocaleTimeString()}
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="bg-muted">
                System Status: Active
              </Badge>
              <Button variant="outline" size="sm" className="h-8 text-xs flex items-center gap-1">
                <Maximize size={14} className="mr-1" />
                Expand View
              </Button>
            </div>
          </CardFooter>
        </>
      )}
      
      {!expanded && (
        <div className="p-4 flex justify-between items-center">
          <div className="flex items-center gap-4">
            <div className="flex items-center">
              <Cpu className="h-4 w-4 text-blue-500 mr-1" />
              <span className={`font-medium ${getMetricColor(currentCPU)}`}>
                {currentCPU}%
              </span>
            </div>
            <div className="flex items-center">
              <Database className="h-4 w-4 text-purple-500 mr-1" />
              <span className={`font-medium ${getMetricColor(currentMemory)}`}>
                {currentMemory}%
              </span>
            </div>
            <div className="flex items-center">
              <HardDrive className="h-4 w-4 text-green-500 mr-1" />
              <span className={`font-medium ${getMetricColor(currentDisk)}`}>
                {currentDisk}%
              </span>
            </div>
            {events.filter(e => e.type === 'critical').length > 0 && (
              <Badge variant="destructive">
                {events.filter(e => e.type === 'critical').length} Critical Alerts
              </Badge>
            )}
          </div>
          <span className="text-xs text-muted-foreground">
            Click to expand
          </span>
        </div>
      )}
    </Card>
  );
};

export default LiveSystemMonitor;
