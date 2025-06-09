
import React, { useState, useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { 
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Circle, Clock, 
  CpuIcon, Database, Download, FileDown, Filter, Globe, HardDrive, Info, 
  Laptop, Lock, Network, Power, RefreshCcw, Server, Shield, Wifi, X, 
  Check, ChevronDown, Search, Settings, Terminal, UsersIcon, DownloadIcon
} from "lucide-react";
import { motion } from "framer-motion";

// Mock data for real-time monitoring
const generateMockData = () => {
  return {
    cpuUsage: Math.floor(Math.random() * 100),
    memoryUsage: Math.floor(Math.random() * 100),
    diskUsage: Math.floor(Math.random() * 100),
    networkIn: Math.floor(Math.random() * 10),
    networkOut: Math.floor(Math.random() * 5),
    temperature: Math.floor(Math.random() * 40) + 30,
    uptime: "21 days, 13 hours, 45 minutes",
    processes: Array.from({ length: 15 }, (_, i) => ({
      pid: Math.floor(Math.random() * 10000),
      name: [`node`, `chrome`, `system`, `nginx`, `python`, `postgres`][Math.floor(Math.random() * 6)],
      user: [`root`, `admin`, `system`, `www-data`][Math.floor(Math.random() * 4)],
      cpu: Math.floor(Math.random() * 100),
      memory: Math.floor(Math.random() * 100),
      status: [`running`, `sleeping`, `waiting`, `zombie`][Math.floor(Math.random() * 4)],
      suspicious: Math.random() > 0.8
    })),
    events: Array.from({ length: 20 }, (_, i) => ({
      id: `evt-${i}`,
      type: [`file_access`, `login`, `network`, `usb`, `scan`][Math.floor(Math.random() * 5)],
      message: [
        "User login from unusual location",
        "File access at /etc/passwd",
        "Network scan detected",
        "USB device inserted",
        "Outbound connection to suspicious IP",
        "System configuration changed",
        "Brute force attempt detected",
        "Unusual file execution",
      ][Math.floor(Math.random() * 8)],
      timestamp: new Date(Date.now() - Math.floor(Math.random() * 36000000)).toISOString(),
      severity: [`critical`, `warning`, `info`][Math.floor(Math.random() * 3)]
    })),
    networkConnections: Array.from({ length: 12 }, (_, i) => ({
      id: `conn-${i}`,
      localIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
      remoteIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      port: Math.floor(Math.random() * 65535),
      protocol: [`TCP`, `UDP`, `HTTP`, `HTTPS`][Math.floor(Math.random() * 4)],
      state: [`ESTABLISHED`, `CLOSED`, `LISTENING`, `TIME_WAIT`][Math.floor(Math.random() * 4)],
      process: [`chrome`, `nginx`, `node`, `system`][Math.floor(Math.random() * 4)]
    })),
    devices: Array.from({ length: 5 }, (_, i) => ({
      id: `dev-${i}`,
      name: [`USB Drive`, `External HDD`, `Webcam`, `Bluetooth Adapter`, `SD Card`][Math.floor(Math.random() * 5)],
      deviceId: `ID-${Math.floor(Math.random() * 10000)}`,
      mountPath: i > 2 ? null : `/mnt/external${i}`,
      timeConnected: new Date(Date.now() - Math.floor(Math.random() * 36000000)).toISOString(),
      isNew: Math.random() > 0.7
    })),
    authEvents: Array.from({ length: 10 }, (_, i) => ({
      id: `auth-${i}`,
      user: [`admin`, `root`, `system`, `guest`, `john`][Math.floor(Math.random() * 5)],
      success: Math.random() > 0.3,
      timestamp: new Date(Date.now() - Math.floor(Math.random() * 86400000)).toISOString(),
      ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
      isAnomaly: Math.random() > 0.8
    })),
    threatScore: Math.floor(Math.random() * 100)
  };
};

const SystemMonitoringDashboard = () => {
  const [data, setData] = useState(generateMockData());
  const [refreshInterval, setRefreshInterval] = useState(5000);
  const [isRefreshing, setIsRefreshing] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [eventFilter, setEventFilter] = useState('all');

  const getHealthStatus = (cpuUsage, memoryUsage, threatScore) => {
    if (cpuUsage > 80 || memoryUsage > 90 || threatScore > 70) return { status: 'Overloaded', color: 'bg-red-500' };
    if (cpuUsage > 60 || memoryUsage > 70 || threatScore > 40) return { status: 'Degraded', color: 'bg-amber-500' };
    return { status: 'Healthy', color: 'bg-green-500' };
  };

  const systemHealth = getHealthStatus(data.cpuUsage, data.memoryUsage, data.threatScore);

  // Simulate real-time data updates
  useEffect(() => {
    let interval;
    
    if (isRefreshing) {
      interval = setInterval(() => {
        setData(generateMockData());
      }, refreshInterval);
    }
    
    return () => clearInterval(interval);
  }, [refreshInterval, isRefreshing]);

  // Filter events based on search term and severity filter
  const filteredEvents = data.events
    .filter(event => eventFilter === 'all' || event.severity === eventFilter)
    .filter(event => 
      event.message.toLowerCase().includes(searchTerm.toLowerCase()) || 
      event.type.toLowerCase().includes(searchTerm.toLowerCase())
    );

  const filteredProcesses = data.processes.filter(process => 
    process.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    process.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
    process.pid.toString().includes(searchTerm)
  );

  // Manual refresh function
  const handleManualRefresh = () => {
    setData(generateMockData());
  };

  // Toggle auto-refresh
  const toggleRefresh = () => {
    setIsRefreshing(!isRefreshing);
  };

  return (
    <div className="p-4 sm:p-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-foreground">System Monitoring Dashboard</h1>
          <p className="text-muted-foreground mt-1">Real-time monitoring and analysis of system resources and activities</p>
        </div>
        <div className="flex items-center mt-4 md:mt-0 space-x-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleManualRefresh} 
            className="flex items-center"
          >
            <RefreshCcw className="mr-1 h-4 w-4" />
            Refresh
          </Button>
          <Button 
            variant={isRefreshing ? "default" : "secondary"} 
            size="sm" 
            onClick={toggleRefresh} 
            className="flex items-center"
          >
            {isRefreshing ? (
              <>
                <Circle className="mr-1 h-4 w-4 fill-current animate-pulse" />
                Live
              </>
            ) : (
              <>
                <Circle className="mr-1 h-4 w-4" />
                Paused
              </>
            )}
          </Button>
          <div className="flex items-center space-x-1 ml-2">
            <span className="text-xs text-muted-foreground">Refresh:</span>
            <select 
              value={refreshInterval} 
              onChange={(e) => setRefreshInterval(Number(e.target.value))} 
              className="text-xs bg-background border border-input rounded-md p-1"
            >
              <option value={1000}>1s</option>
              <option value={3000}>3s</option>
              <option value={5000}>5s</option>
              <option value={10000}>10s</option>
            </select>
          </div>
        </div>
      </div>

      {/* System Status Overview Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <Server className="mr-2 h-5 w-5 text-primary" />
              System Overview
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col space-y-1">
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Hostname:</span>
                <span className="text-sm font-medium">isimbi-server-prod-01</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">OS Type:</span>
                <span className="text-sm font-medium">Ubuntu 24.04 LTS</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">CPU Model:</span>
                <span className="text-sm font-medium">AMD EPYC 7543 32-Core</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Total RAM:</span>
                <span className="text-sm font-medium">128 GB DDR4</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Uptime:</span>
                <span className="text-sm font-medium">{data.uptime}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <Activity className="mr-2 h-5 w-5 text-primary" />
              System Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-center h-20">
              <div className="text-center">
                <div className="flex items-center justify-center">
                  <div className={`h-12 w-12 rounded-full ${systemHealth.color} flex items-center justify-center`}>
                    {systemHealth.status === 'Healthy' ? (
                      <Check className="h-6 w-6 text-white" />
                    ) : systemHealth.status === 'Degraded' ? (
                      <AlertTriangle className="h-6 w-6 text-white" />
                    ) : (
                      <X className="h-6 w-6 text-white" />
                    )}
                  </div>
                </div>
                <div className="mt-2 font-bold text-xl">{systemHealth.status}</div>
                <div className="text-xs text-muted-foreground">Last updated: {new Date().toLocaleTimeString()}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <Shield className="mr-2 h-5 w-5 text-primary" />
              Security Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col space-y-3">
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-sm">Threat Risk Score</span>
                  <span className="text-sm font-medium">
                    {data.threatScore} / 100
                    {data.threatScore < 30 ? (
                      <Badge variant="outline" className="ml-2 bg-green-500/10 text-green-500 border-green-500/20">Low</Badge>
                    ) : data.threatScore < 70 ? (
                      <Badge variant="outline" className="ml-2 bg-amber-500/10 text-amber-500 border-amber-500/20">Medium</Badge>
                    ) : (
                      <Badge variant="outline" className="ml-2 bg-red-500/10 text-red-500 border-red-500/20">High</Badge>
                    )}
                  </span>
                </div>
                <Progress 
                  value={data.threatScore} 
                  className={`h-2 ${
                    data.threatScore < 30 ? "bg-green-100 [&>div]:bg-green-500" : 
                    data.threatScore < 70 ? "bg-amber-100 [&>div]:bg-amber-500" : 
                    "bg-red-100 [&>div]:bg-red-500"
                  }`} 
                />
              </div>
              <div className="grid grid-cols-2 gap-2 mt-2">
                <div className="flex items-center">
                  <div className={`h-2 w-2 rounded-full ${data.events.filter(e => e.severity === 'critical').length > 0 ? 'bg-red-500' : 'bg-gray-300'} mr-2`}></div>
                  <span className="text-xs">Critical Alerts</span>
                </div>
                <div className="flex items-center">
                  <div className={`h-2 w-2 rounded-full ${data.authEvents.filter(a => a.isAnomaly).length > 0 ? 'bg-amber-500' : 'bg-gray-300'} mr-2`}></div>
                  <span className="text-xs">Auth Anomalies</span>
                </div>
                <div className="flex items-center">
                  <div className={`h-2 w-2 rounded-full ${data.processes.filter(p => p.suspicious).length > 0 ? 'bg-amber-500' : 'bg-gray-300'} mr-2`}></div>
                  <span className="text-xs">Suspect Processes</span>
                </div>
                <div className="flex items-center">
                  <div className={`h-2 w-2 rounded-full ${data.devices.filter(d => d.isNew).length > 0 ? 'bg-blue-500' : 'bg-gray-300'} mr-2`}></div>
                  <span className="text-xs">New Devices</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Dashboard Tabs */}
      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 mb-4 h-auto">
          <TabsTrigger value="overview" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Activity className="mr-2 h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="processes" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Terminal className="mr-2 h-4 w-4" />
            Processes
          </TabsTrigger>
          <TabsTrigger value="events" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <AlertTriangle className="mr-2 h-4 w-4" />
            Events Log
          </TabsTrigger>
          <TabsTrigger value="resources" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <CpuIcon className="mr-2 h-4 w-4" />
            Resources
          </TabsTrigger>
          <TabsTrigger value="network" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Network className="mr-2 h-4 w-4" />
            Network
          </TabsTrigger>
          <TabsTrigger value="devices" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <HardDrive className="mr-2 h-4 w-4" />
            Devices
          </TabsTrigger>
          <TabsTrigger value="auth" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Lock className="mr-2 h-4 w-4" />
            Auth
          </TabsTrigger>
          <TabsTrigger value="behavior" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <UsersIcon className="mr-2 h-4 w-4" />
            Behavior
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab Content */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* CPU Usage Card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <CpuIcon className="mr-2 h-4 w-4 text-primary" />
                  CPU Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{data.cpuUsage}%</div>
                <Progress value={data.cpuUsage} className="h-2" />
                <div className="mt-2 text-xs text-muted-foreground flex items-center">
                  {data.cpuUsage > data.cpuUsage - 5 ? (
                    <ArrowUpRight className="h-3 w-3 mr-1 text-red-500" />
                  ) : (
                    <ArrowDownRight className="h-3 w-3 mr-1 text-green-500" />
                  )}
                  <span>{Math.abs(data.cpuUsage - (data.cpuUsage - 5))}% from previous</span>
                </div>
              </CardContent>
            </Card>
            
            {/* Memory Usage Card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <Database className="mr-2 h-4 w-4 text-primary" />
                  Memory Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{data.memoryUsage}%</div>
                <Progress value={data.memoryUsage} className="h-2" />
                <div className="mt-2 text-xs text-muted-foreground flex items-center">
                  {data.memoryUsage > data.memoryUsage - 3 ? (
                    <ArrowUpRight className="h-3 w-3 mr-1 text-red-500" />
                  ) : (
                    <ArrowDownRight className="h-3 w-3 mr-1 text-green-500" />
                  )}
                  <span>{Math.abs(data.memoryUsage - (data.memoryUsage - 3))}% from previous</span>
                </div>
              </CardContent>
            </Card>
            
            {/* Disk Usage Card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <HardDrive className="mr-2 h-4 w-4 text-primary" />
                  Disk Usage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{data.diskUsage}%</div>
                <Progress value={data.diskUsage} className="h-2" />
                <div className="mt-2 text-xs text-muted-foreground flex items-center">
                  <span>980 GB free of 2 TB</span>
                </div>
              </CardContent>
            </Card>
            
            {/* Network Traffic Card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <Wifi className="mr-2 h-4 w-4 text-primary" />
                  Network Traffic
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <div className="text-xs text-muted-foreground">Download</div>
                    <div className="flex items-center">
                      <ArrowDownRight className="h-4 w-4 mr-1 text-green-500" />
                      <span className="text-lg font-semibold">{data.networkIn} MB/s</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Upload</div>
                    <div className="flex items-center">
                      <ArrowUpRight className="h-4 w-4 mr-1 text-blue-500" />
                      <span className="text-lg font-semibold">{data.networkOut} MB/s</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Recent Events */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5 text-primary" />
                  Recent Events
                </CardTitle>
                <CardDescription>Latest system events and notifications</CardDescription>
              </CardHeader>
              <CardContent className="max-h-[300px] overflow-y-auto">
                <div className="space-y-2">
                  {data.events.slice(0, 5).map((event) => (
                    <div key={event.id} className="flex items-start p-2 rounded-md bg-accent/30">
                      <div className={`mt-0.5 h-2 w-2 rounded-full mr-2 ${
                        event.severity === 'critical' ? 'bg-red-500' : 
                        event.severity === 'warning' ? 'bg-amber-500' : 'bg-blue-500'
                      }`}></div>
                      <div className="flex-grow">
                        <div className="text-sm">{event.message}</div>
                        <div className="flex items-center text-xs text-muted-foreground">
                          <Clock className="h-3 w-3 mr-1" />
                          {new Date(event.timestamp).toLocaleString()}
                        </div>
                      </div>
                      <Badge variant="outline" className={`ml-2 ${
                        event.severity === 'critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                        event.severity === 'warning' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' : 
                        'bg-blue-500/10 text-blue-500 border-blue-500/20'
                      }`}>
                        {event.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" className="w-full" size="sm">
                  View All Events
                </Button>
              </CardFooter>
            </Card>

            {/* Control Panel */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center">
                  <Settings className="mr-2 h-5 w-5 text-primary" />
                  Control Panel
                </CardTitle>
                <CardDescription>System actions and controls</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <Button className="w-full justify-start">
                    <Shield className="mr-2 h-4 w-4" />
                    Run Security Scan
                  </Button>
                  <Button variant="outline" className="w-full justify-start">
                    <Power className="mr-2 h-4 w-4" />
                    Optimize System
                  </Button>
                  <Button variant="outline" className="w-full justify-start">
                    <Download className="mr-2 h-4 w-4" />
                    Download Logs
                  </Button>
                  
                  <Separator className="my-3" />
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Real-time Monitoring</span>
                    <div className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out ${isRefreshing ? 'bg-primary' : 'bg-gray-200 dark:bg-gray-700'}`}>
                      <span 
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${isRefreshing ? 'translate-x-4' : 'translate-x-0'}`}
                      ></span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Alert Sounds</span>
                    <div className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent bg-gray-200 dark:bg-gray-700 transition-colors duration-200 ease-in-out">
                      <span 
                        className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-0"
                      ></span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Auto-Response</span>
                    <div className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent bg-primary transition-colors duration-200 ease-in-out">
                      <span 
                        className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-4"
                      ></span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Processes Tab Content */}
        <TabsContent value="processes" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <div className="flex flex-col md:flex-row md:items-center justify-between">
                <CardTitle className="text-lg flex items-center">
                  <Terminal className="mr-2 h-5 w-5 text-primary" />
                  Active System Processes
                </CardTitle>
                <div className="flex mt-2 md:mt-0">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search processes..."
                      className="pl-8 pr-4 py-2 text-sm rounded-md border border-input bg-background"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/50">
                        <th className="py-3 px-4 text-left font-medium">PID</th>
                        <th className="py-3 px-4 text-left font-medium">Name</th>
                        <th className="py-3 px-4 text-left font-medium">User</th>
                        <th className="py-3 px-4 text-left font-medium">CPU %</th>
                        <th className="py-3 px-4 text-left font-medium">Memory %</th>
                        <th className="py-3 px-4 text-left font-medium">Status</th>
                        <th className="py-3 px-4 text-center font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredProcesses.map((process) => (
                        <tr 
                          key={process.pid} 
                          className={`border-t ${process.suspicious ? 'bg-red-50 dark:bg-red-900/10' : ''}`}
                        >
                          <td className="py-2 px-4">{process.pid}</td>
                          <td className="py-2 px-4 font-medium flex items-center">
                            {process.suspicious && <AlertTriangle className="mr-1 h-4 w-4 text-red-500" />}
                            {process.name}
                          </td>
                          <td className="py-2 px-4">{process.user}</td>
                          <td className="py-2 px-4">
                            <div className="flex items-center">
                              <div className="w-12 h-2 bg-muted rounded-full overflow-hidden mr-2">
                                <div 
                                  className={`h-full rounded-full ${
                                    process.cpu > 70 ? 'bg-red-500' : 
                                    process.cpu > 30 ? 'bg-amber-500' : 'bg-green-500'
                                  }`} 
                                  style={{width: `${process.cpu}%`}}
                                ></div>
                              </div>
                              {process.cpu}%
                            </div>
                          </td>
                          <td className="py-2 px-4">
                            <div className="flex items-center">
                              <div className="w-12 h-2 bg-muted rounded-full overflow-hidden mr-2">
                                <div 
                                  className={`h-full rounded-full ${
                                    process.memory > 70 ? 'bg-red-500' : 
                                    process.memory > 30 ? 'bg-amber-500' : 'bg-green-500'
                                  }`} 
                                  style={{width: `${process.memory}%`}}
                                ></div>
                              </div>
                              {process.memory}%
                            </div>
                          </td>
                          <td className="py-2 px-4">
                            <Badge variant="outline" className={
                              process.status === 'running' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 
                              process.status === 'sleeping' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 
                              process.status === 'waiting' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' : 
                              'bg-red-500/10 text-red-500 border-red-500/20'
                            }>
                              {process.status}
                            </Badge>
                          </td>
                          <td className="py-2 px-4">
                            <div className="flex justify-center space-x-1">
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Terminate</span>
                                <X className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Quarantine</span>
                                <Shield className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Mark Safe</span>
                                <Check className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </CardContent>
            <CardFooter className="flex justify-between items-center">
              <div className="text-sm text-muted-foreground">
                Showing {filteredProcesses.length} of {data.processes.length} processes
              </div>
              <div className="flex items-center space-x-2">
                <Button variant="outline" size="sm">Previous</Button>
                <Button variant="outline" size="sm">Next</Button>
              </div>
            </CardFooter>
          </Card>
        </TabsContent>

        {/* Events Log Tab Content */}
        <TabsContent value="events" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <div className="flex flex-col md:flex-row md:items-center justify-between">
                <CardTitle className="text-lg flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5 text-primary" />
                  System Events Log
                </CardTitle>
                <div className="flex mt-2 md:mt-0 space-x-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search events..."
                      className="pl-8 pr-4 py-2 text-sm rounded-md border border-input bg-background"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                  <div className="flex items-center space-x-1">
                    <Button 
                      size="sm"
                      variant={eventFilter === 'all' ? "default" : "ghost"} 
                      onClick={() => setEventFilter('all')}
                    >
                      All
                    </Button>
                    <Button 
                      size="sm"
                      variant={eventFilter === 'critical' ? "default" : "ghost"} 
                      className={eventFilter === 'critical' ? "" : "text-red-500"}
                      onClick={() => setEventFilter('critical')}
                    >
                      Critical
                    </Button>
                    <Button 
                      size="sm"
                      variant={eventFilter === 'warning' ? "default" : "ghost"}
                      className={eventFilter === 'warning' ? "" : "text-amber-500"}
                      onClick={() => setEventFilter('warning')}
                    >
                      Warning
                    </Button>
                    <Button 
                      size="sm"
                      variant={eventFilter === 'info' ? "default" : "ghost"}
                      className={eventFilter === 'info' ? "" : "text-blue-500"}
                      onClick={() => setEventFilter('info')}
                    >
                      Info
                    </Button>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {filteredEvents.map((event) => (
                  <div 
                    key={event.id} 
                    className={`p-3 rounded-md ${
                      event.severity === 'critical' ? 'bg-red-50 dark:bg-red-900/10 border-l-2 border-red-500' : 
                      event.severity === 'warning' ? 'bg-amber-50 dark:bg-amber-900/10 border-l-2 border-amber-500' : 
                      'bg-blue-50 dark:bg-blue-900/10 border-l-2 border-blue-500'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between">
                      <div className="flex items-start">
                        <div className="mr-3">
                          {event.severity === 'critical' ? (
                            <div className="h-6 w-6 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center">
                              <AlertTriangle className="h-4 w-4 text-red-500" />
                            </div>
                          ) : event.severity === 'warning' ? (
                            <div className="h-6 w-6 rounded-full bg-amber-100 dark:bg-amber-900/20 flex items-center justify-center">
                              <AlertTriangle className="h-4 w-4 text-amber-500" />
                            </div>
                          ) : (
                            <div className="h-6 w-6 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                              <Info className="h-4 w-4 text-blue-500" />
                            </div>
                          )}
                        </div>
                        <div>
                          <div className="font-medium">{event.message}</div>
                          <div className="text-xs text-muted-foreground mt-0.5">
                            Event Type: {event.type.replace('_', ' ')}
                          </div>
                        </div>
                      </div>
                      <div className="mt-2 sm:mt-0 flex items-center text-xs text-muted-foreground">
                        <Clock className="h-3 w-3 mr-1" />
                        {new Date(event.timestamp).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="text-sm text-muted-foreground">
                Showing {filteredEvents.length} of {data.events.length} events
              </div>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm" className="flex items-center">
                  <FileDown className="mr-1 h-4 w-4" />
                  Export CSV
                </Button>
                <Button variant="outline" size="sm" className="flex items-center">
                  <DownloadIcon className="mr-1 h-4 w-4" />
                  Export JSON
                </Button>
              </div>
            </CardFooter>
          </Card>
        </TabsContent>

        {/* Resource Usage Tab Content - simplified version */}
        <TabsContent value="resources" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <CpuIcon className="mr-2 h-5 w-5 text-primary" />
                Resource Utilization
              </CardTitle>
              <CardDescription>Real-time system resource monitoring</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* CPU Usage Chart (simplified mock) */}
                <div>
                  <h3 className="text-sm font-medium mb-2">CPU Utilization</h3>
                  <div className="aspect-[4/3] bg-muted/20 rounded-md p-4 relative">
                    {/* Mock CPU chart visualization */}
                    <div className="absolute inset-0 flex items-end p-4">
                      {[...Array(20)].map((_, i) => (
                        <div 
                          key={i} 
                          className="flex-1 mx-0.5"
                          style={{
                            height: `${10 + Math.random() * 80}%`,
                            backgroundColor: `rgba(125, 135, 255, ${0.3 + Math.random() * 0.7})`
                          }}
                        ></div>
                      ))}
                    </div>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-3xl font-bold">{data.cpuUsage}%</div>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-2 mt-2">
                    <div className="text-xs">
                      <div className="font-medium">Core 1</div>
                      <div className="text-muted-foreground">{Math.floor(Math.random() * 100)}%</div>
                    </div>
                    <div className="text-xs">
                      <div className="font-medium">Core 2</div>
                      <div className="text-muted-foreground">{Math.floor(Math.random() * 100)}%</div>
                    </div>
                    <div className="text-xs">
                      <div className="font-medium">Core 3</div>
                      <div className="text-muted-foreground">{Math.floor(Math.random() * 100)}%</div>
                    </div>
                    <div className="text-xs">
                      <div className="font-medium">Core 4</div>
                      <div className="text-muted-foreground">{Math.floor(Math.random() * 100)}%</div>
                    </div>
                  </div>
                </div>
                
                {/* Memory Usage Chart (simplified mock) */}
                <div>
                  <h3 className="text-sm font-medium mb-2">Memory Utilization</h3>
                  <div className="aspect-[4/3] bg-muted/20 rounded-md p-4 relative">
                    {/* Mock memory chart visualization */}
                    <div className="h-full flex flex-col justify-end">
                      <div 
                        className="bg-isimbi-purple/70 w-full rounded-t-sm"
                        style={{ height: `${data.memoryUsage}%` }}
                      ></div>
                    </div>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-3xl font-bold">{data.memoryUsage}%</div>
                        <div className="text-xs text-muted-foreground">of 128 GB</div>
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-3 mt-2">
                    <div className="bg-muted/20 p-2 rounded">
                      <div className="text-xs font-medium">Used</div>
                      <div className="text-sm">{Math.round(128 * data.memoryUsage / 100)} GB</div>
                    </div>
                    <div className="bg-muted/20 p-2 rounded">
                      <div className="text-xs font-medium">Free</div>
                      <div className="text-sm">{128 - Math.round(128 * data.memoryUsage / 100)} GB</div>
                    </div>
                    <div className="bg-muted/20 p-2 rounded">
                      <div className="text-xs font-medium">Cached</div>
                      <div className="text-sm">{Math.round(Math.random() * 40)} GB</div>
                    </div>
                  </div>
                </div>
                
                {/* Disk I/O Chart (simplified mock) */}
                <div>
                  <h3 className="text-sm font-medium mb-2">Disk I/O</h3>
                  <div className="aspect-[4/3] bg-muted/20 rounded-md p-4 flex flex-col justify-center">
                    <div className="mb-4">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs">Read</span>
                        <span className="text-xs font-medium">{Math.floor(Math.random() * 100)} MB/s</span>
                      </div>
                      <Progress value={Math.random() * 100} className="h-1" />
                    </div>
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs">Write</span>
                        <span className="text-xs font-medium">{Math.floor(Math.random() * 50)} MB/s</span>
                      </div>
                      <Progress value={Math.random() * 100} className="h-1" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="text-xs">
                      <div className="font-medium">Avg. Read Latency</div>
                      <div className="text-muted-foreground">{(Math.random() * 10).toFixed(2)} ms</div>
                    </div>
                    <div className="text-xs">
                      <div className="font-medium">Avg. Write Latency</div>
                      <div className="text-muted-foreground">{(Math.random() * 15).toFixed(2)} ms</div>
                    </div>
                  </div>
                </div>
                
                {/* Network Traffic Chart (simplified mock) */}
                <div>
                  <h3 className="text-sm font-medium mb-2">Network Traffic</h3>
                  <div className="aspect-[4/3] bg-muted/20 rounded-md p-4 relative">
                    {/* Mock network chart visualization */}
                    <div className="absolute inset-0 flex items-end p-4">
                      <div className="w-full h-full flex items-end">
                        {[...Array(20)].map((_, i) => (
                          <div key={i} className="relative flex-1 mx-0.5">
                            <div 
                              className="absolute bottom-0 left-0 right-0 bg-green-500/70"
                              style={{ height: `${10 + Math.random() * 60}%` }}
                            ></div>
                            <div 
                              className="absolute bottom-0 left-0 right-0 bg-blue-500/70"
                              style={{ height: `${10 + Math.random() * 30}%` }}
                            ></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="flex items-center text-xs">
                      <div className="w-3 h-3 bg-green-500/70 mr-1.5"></div>
                      <div>
                        <div className="font-medium">Download</div>
                        <div className="text-muted-foreground">{data.networkIn} MB/s</div>
                      </div>
                    </div>
                    <div className="flex items-center text-xs">
                      <div className="w-3 h-3 bg-blue-500/70 mr-1.5"></div>
                      <div>
                        <div className="font-medium">Upload</div>
                        <div className="text-muted-foreground">{data.networkOut} MB/s</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Network Connections Tab Content */}
        <TabsContent value="network" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <div className="flex flex-col md:flex-row md:items-center justify-between">
                <CardTitle className="text-lg flex items-center">
                  <Network className="mr-2 h-5 w-5 text-primary" />
                  Network Connections
                </CardTitle>
                <div className="flex mt-2 md:mt-0">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search connections..."
                      className="pl-8 pr-4 py-2 text-sm rounded-md border border-input bg-background"
                    />
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/50">
                        <th className="py-3 px-4 text-left font-medium">Local IP</th>
                        <th className="py-3 px-4 text-left font-medium">Remote IP</th>
                        <th className="py-3 px-4 text-left font-medium">Port</th>
                        <th className="py-3 px-4 text-left font-medium">Protocol</th>
                        <th className="py-3 px-4 text-left font-medium">State</th>
                        <th className="py-3 px-4 text-left font-medium">Process</th>
                        <th className="py-3 px-4 text-center font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.networkConnections.map((connection) => (
                        <tr key={connection.id} className="border-t">
                          <td className="py-2 px-4">{connection.localIp}</td>
                          <td className="py-2 px-4 font-medium">
                            {connection.remoteIp}
                            {connection.remoteIp.startsWith('192.168') && (
                              <Badge variant="outline" className="ml-2 bg-blue-500/10 text-blue-500 border-blue-500/20">
                                Local
                              </Badge>
                            )}
                          </td>
                          <td className="py-2 px-4">{connection.port}</td>
                          <td className="py-2 px-4">{connection.protocol}</td>
                          <td className="py-2 px-4">
                            <Badge variant="outline" className={
                              connection.state === 'ESTABLISHED' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 
                              connection.state === 'LISTENING' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' : 
                              connection.state === 'CLOSED' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                              'bg-amber-500/10 text-amber-500 border-amber-500/20'
                            }>
                              {connection.state}
                            </Badge>
                          </td>
                          <td className="py-2 px-4">{connection.process}</td>
                          <td className="py-2 px-4">
                            <div className="flex justify-center space-x-1">
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Block IP</span>
                                <X className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Trace Route</span>
                                <Network className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Allow</span>
                                <Check className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              
              {/* Mock GeoIP Map */}
              <div className="mt-4">
                <h3 className="text-sm font-medium mb-2">Connection Map</h3>
                <div className="aspect-[16/9] bg-muted/20 rounded-md p-4 flex items-center justify-center">
                  <div className="text-center text-muted-foreground">
                    <Globe className="h-10 w-10 mb-2 mx-auto opacity-50" />
                    <p>GeoIP Map of Remote Connections</p>
                    <p className="text-xs">(Actual map would render here in production)</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Devices & Peripherals Tab Content */}
        <TabsContent value="devices" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <HardDrive className="mr-2 h-5 w-5 text-primary" />
                Connected Devices & Peripherals
              </CardTitle>
              <CardDescription>Monitor devices connected to the system</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/50">
                        <th className="py-3 px-4 text-left font-medium">Device Name</th>
                        <th className="py-3 px-4 text-left font-medium">Device ID</th>
                        <th className="py-3 px-4 text-left font-medium">Mount Path</th>
                        <th className="py-3 px-4 text-left font-medium">Time Connected</th>
                        <th className="py-3 px-4 text-center font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.devices.map((device) => (
                        <tr key={device.id} className={`border-t ${device.isNew ? 'bg-blue-50 dark:bg-blue-900/10' : ''}`}>
                          <td className="py-2 px-4 font-medium flex items-center">
                            {device.isNew && (
                              <Badge variant="outline" className="mr-2 bg-blue-500/10 text-blue-500 border-blue-500/20">
                                NEW
                              </Badge>
                            )}
                            {device.name}
                          </td>
                          <td className="py-2 px-4">{device.deviceId}</td>
                          <td className="py-2 px-4">{device.mountPath || 'Not mounted'}</td>
                          <td className="py-2 px-4">
                            {new Date(device.timeConnected).toLocaleString()}
                          </td>
                          <td className="py-2 px-4">
                            <div className="flex justify-center space-x-1">
                              {device.mountPath && (
                                <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                  <span className="sr-only">Eject</span>
                                  <Laptop className="h-4 w-4" />
                                </Button>
                              )}
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0">
                                <span className="sr-only">Quarantine</span>
                                <Shield className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-8 w-8 p-0 text-red-500">
                                <span className="sr-only">Block</span>
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              
              <div className="mt-6">
                <h3 className="text-sm font-medium mb-3">Device Monitoring Settings</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Auto-Detect New USB Devices</div>
                      <div className="text-xs text-muted-foreground">Automatically detect and monitor new USB devices</div>
                    </div>
                    <div className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent bg-primary transition-colors duration-200 ease-in-out">
                      <span className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-4"></span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Block Unknown USB Storage</div>
                      <div className="text-xs text-muted-foreground">Block USB storage devices not in allow list</div>
                    </div>
                    <div className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out bg-gray-200 dark:bg-gray-700">
                      <span className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-0"></span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Alert on Device Connect/Disconnect</div>
                      <div className="text-xs text-muted-foreground">Send notifications for device events</div>
                    </div>
                    <div className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent bg-primary transition-colors duration-200 ease-in-out">
                      <span className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-4"></span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Auth Events Tab Content */}
        <TabsContent value="auth" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <Lock className="mr-2 h-5 w-5 text-primary" />
                Authentication Events
              </CardTitle>
              <CardDescription>Recent login attempts and privilege escalations</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {data.authEvents.map((event) => (
                  <div 
                    key={event.id} 
                    className={`p-3 rounded-md border ${
                      event.isAnomaly ? 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-800' : 
                      !event.success ? 'bg-amber-50 dark:bg-amber-900/10 border-amber-200 dark:border-amber-800' : 
                      'bg-muted/20'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between">
                      <div className="flex items-center">
                        <div className="mr-3">
                          {event.isAnomaly ? (
                            <div className="h-8 w-8 rounded-full bg-red-100 dark:bg-red-900/20 flex items-center justify-center">
                              <AlertTriangle className="h-5 w-5 text-red-500" />
                            </div>
                          ) : event.success ? (
                            <div className="h-8 w-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                              <Check className="h-5 w-5 text-green-500" />
                            </div>
                          ) : (
                            <div className="h-8 w-8 rounded-full bg-amber-100 dark:bg-amber-900/20 flex items-center justify-center">
                              <X className="h-5 w-5 text-amber-500" />
                            </div>
                          )}
                        </div>
                        <div>
                          <div className="font-medium">
                            {event.success ? 'Successful login' : 'Failed login attempt'} as {event.user}
                            {event.isAnomaly && <span className="text-red-500 ml-1">(Anomalous behavior)</span>}
                          </div>
                          <div className="text-xs text-muted-foreground mt-0.5">
                            From IP: {event.ip}
                          </div>
                        </div>
                      </div>
                      <div className="mt-2 sm:mt-0 flex items-center text-xs text-muted-foreground">
                        <Clock className="h-3 w-3 mr-1" />
                        {new Date(event.timestamp).toLocaleString()}
                      </div>
                    </div>
                    
                    {event.isAnomaly && (
                      <div className="mt-2 text-sm bg-red-100 dark:bg-red-900/20 p-2 rounded border border-red-200 dark:border-red-800">
                        <span className="font-medium text-red-700 dark:text-red-400">Risk details:</span> Unusual login time or location detected for this user.
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* User Behavior Tab Content */}
        <TabsContent value="behavior" className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <UsersIcon className="mr-2 h-5 w-5 text-primary" />
                User Behavior Analysis
              </CardTitle>
              <CardDescription>Monitor and analyze user activity patterns</CardDescription>
            </CardHeader>
            <CardContent>
              {/* Mock Heatmap */}
              <div className="mb-8">
                <h3 className="text-sm font-medium mb-3">Daily Activity Heatmap</h3>
                <div className="bg-muted/20 rounded-md p-4">
                  <div className="grid grid-cols-24 gap-1 mb-2">
                    {[...Array(24)].map((_, i) => (
                      <div key={i} className="text-xs text-center text-muted-foreground">
                        {i}h
                      </div>
                    ))}
                  </div>
                  <div className="space-y-2">
                    {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day) => (
                      <div key={day} className="flex items-center">
                        <div className="w-8 text-xs text-muted-foreground">{day}</div>
                        <div className="flex-1 grid grid-cols-24 gap-1">
                          {[...Array(24)].map((_, i) => {
                            const activityLevel = Math.random();
                            let bgColor = 'bg-green-100 dark:bg-green-900/10';
                            if (activityLevel > 0.7) bgColor = 'bg-green-500';
                            else if (activityLevel > 0.4) bgColor = 'bg-green-400';
                            else if (activityLevel > 0.2) bgColor = 'bg-green-300';
                            else if (activityLevel > 0.1) bgColor = 'bg-green-200';
                            
                            return (
                              <div 
                                key={i}
                                className={`h-6 rounded-sm ${bgColor}`}
                                title={`${day} ${i}:00 - Activity level: ${Math.round(activityLevel * 100)}%`}
                              ></div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-end items-center mt-2 space-x-2">
                    <div className="text-xs text-muted-foreground">Activity level:</div>
                    <div className="flex items-center space-x-1">
                      <div className="w-3 h-3 bg-green-100 dark:bg-green-900/10 rounded-sm"></div>
                      <div className="w-3 h-3 bg-green-200 rounded-sm"></div>
                      <div className="w-3 h-3 bg-green-300 rounded-sm"></div>
                      <div className="w-3 h-3 bg-green-400 rounded-sm"></div>
                      <div className="w-3 h-3 bg-green-500 rounded-sm"></div>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Behavior Deviation Graph (simplified mock) */}
              <div>
                <h3 className="text-sm font-medium mb-3">Behavior Deviation Analysis</h3>
                <div className="bg-muted/20 rounded-md p-4 aspect-[3/1]">
                  <div className="relative h-full w-full">
                    <div className="absolute inset-x-0 bottom-0 border-t border-border opacity-30"></div>
                    <div className="absolute inset-x-0 bottom-1/4 border-t border-border opacity-30"></div>
                    <div className="absolute inset-x-0 bottom-2/4 border-t border-border opacity-30"></div>
                    <div className="absolute inset-x-0 bottom-3/4 border-t border-border opacity-30"></div>
                    
                    <div className="absolute bottom-0 left-0 right-0 h-full">
                      <svg className="h-full w-full">
                        <path 
                          d={`M0,${(1-Math.random()*0.3)*100} ${[...Array(30)].map((_, i) => `L${(i+1)*(100/30)},${(1-Math.random()*0.3)*100}`).join(' ')}`}
                          fill="none" 
                          stroke="rgba(34, 197, 94, 0.5)" 
                          strokeWidth="2"
                        />
                        <path 
                          d={`M0,${(1-Math.random()*0.3-0.3)*100} ${[...Array(30)].map((_, i) => `L${(i+1)*(100/30)},${(1-Math.random()*0.3-0.3)*100}`).join(' ')}`}
                          fill="none" 
                          stroke="rgba(245, 158, 11, 0.5)" 
                          strokeWidth="2"
                        />
                        <path 
                          d={`M0,${(1-Math.random()*0.2-0.7)*100} ${[...Array(30)].map((_, i) => {
                            // Add a spike for anomaly
                            const spike = i === 20 ? 0.5 : 0;
                            return `L${(i+1)*(100/30)},${(1-Math.random()*0.2-0.7+spike)*100}`;
                          }).join(' ')}`}
                          fill="none" 
                          stroke="rgba(239, 68, 68, 0.5)" 
                          strokeWidth="2"
                        />
                        
                        {/* Anomaly point */}
                        <circle cx="66.7" cy="25" r="4" fill="rgba(239, 68, 68, 1)" />
                      </svg>
                    </div>
                  </div>
                </div>
                <div className="flex justify-between mt-2">
                  <div className="flex items-center space-x-3 text-xs">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-green-500/50 mr-1.5 rounded-full"></div>
                      <span>Normal</span>
                    </div>
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-amber-500/50 mr-1.5 rounded-full"></div>
                      <span>Warning</span>
                    </div>
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-red-500/50 mr-1.5 rounded-full"></div>
                      <span>Critical</span>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">Past 30 days</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SystemMonitoringDashboard;
