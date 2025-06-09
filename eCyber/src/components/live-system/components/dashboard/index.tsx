
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Bell, RefreshCw, Wifi, WifiOff, Shield, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useSelector } from "react-redux";

import { useTelemetrySocket } from "../../lib/socket";
import { StatusCard } from "./StatusCard";
import { Charts } from "./Charts";
import { ProcessMonitor } from "./ProcessMonitor";
import { NetworkConnections } from "./NetworkConnections";
import { AnomaliesPanel } from "./AnomaliesPanel";
import { SecurityOverview } from "./SecurityOverview";
import { NetworkInterfaces } from "./NetworkInterfaces";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { formatBytes, cn } from "../../lib/utils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import { RootState } from "@/app/store";

import { SystemTelemetryData } from "../../lib/socket";
import { SecurityItem } from "../../lib/socket";

export function SystemDashboard() {

  const { getSocket,

    disconnectSocket,
    getMockTelemetryData,
    isOfflineMode,
    enableOfflineMode,
    disableOfflineMode,
    
    threatDetectionService } = useTelemetrySocket();
  
  const cached = localStorage.getItem('lastTelemetry');
  const initialTelemetry: SystemTelemetryData | null = cached
    ? JSON.parse(cached)
    : null;
  
  const [telemetryData, setTelemetryData] = useState<SystemTelemetryData | null>(initialTelemetry);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(
    initialTelemetry ? new Date(JSON.parse(cached!)!.timestamp) : new Date()
  );
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(5);
  const [offline, setOffline] = useState(isOfflineMode());
  const [securityRecommendations, setSecurityRecommendations] = useState<SecurityItem[]>([]);
  const [securityDialogOpen, setSecurityDialogOpen] = useState(false);
  const [threatLevel, setThreatLevel] = useState<'low' | 'medium' | 'high'>('low');

    
  

  useEffect(() => {
    // If we're in offline mode, use mock data
    // if (offline) {
    //   const mockData = getMockTelemetryData();
    //   setTelemetryData(mockData);
    //   setLastUpdate(new Date());
      
    //   // Generate security recommendations
    //   const recommendations = threatDetectionService.generateSecurityRecommendations(mockData);
    //   setSecurityRecommendations(recommendations);
      
    //   // Calculate threat level
    //   calculateThreatLevel(mockData);
    //   return;
    // }

    const socket = getSocket();
    
    // Handle real-time data from the socket
    const handleTelemetryData = (data: SystemTelemetryData) => {
      // Add additional CPU/Memory details
      if (data.systemOverview) {
        const cpuItem = data.systemOverview.find(item => item.title === "CPU Usage");
        if (cpuItem && data.cpuDetails) {
          cpuItem.details = `${data.cpuDetails.cores.physical} physical cores, ${data.cpuDetails.cores.logical} logical cores`;
        }

        const memoryItem = data.systemOverview.find(item => item.title === "Memory Usage");
        if (memoryItem && data.memoryDetails) {
          memoryItem.details = `${formatBytes(data.memoryDetails.used)} used of ${formatBytes(data.memoryDetails.total)}`;
        }
      }

      setTelemetryData(data);
      localStorage.setItem('lastTelemetry', JSON.stringify(data));
      setLastUpdate(new Date());
      
      // Generate security recommendations
      const recommendations = threatDetectionService.generateSecurityRecommendations(data);
      setSecurityRecommendations(recommendations);
      
      // Calculate threat level
      calculateThreatLevel(data);
      
      // Show notification for new anomalies if they exist
      if (data.anomalies && data.anomalies.length > 0) {
        const highSeverityAnomalies = data.anomalies.filter(a => a.severity === 'high');
        if (highSeverityAnomalies.length > 0) {
          toast.error(`${highSeverityAnomalies.length} high severity anomalies detected`, {
            description: highSeverityAnomalies[0].title,
            action: {
              label: "View",
              onClick: () => {
                const anomalySection = document.getElementById('anomalies-section');
                if (anomalySection) {
                  anomalySection.scrollIntoView({ behavior: 'smooth' });
                }
              }
            }
          });
        }
      }
    };

    if (socket) {
      socket.on('system_telemetry', handleTelemetryData);
      socket.on('ips_mitigation', (data:any) => console.log("Mitigation data: ", data))
    };

    // Check offline status periodically
    const checkOfflineStatus = () => {
      const currentOfflineStatus = isOfflineMode();
      if (offline !== currentOfflineStatus) {
        setOffline(currentOfflineStatus);
      }
    };

    const offlineStatusInterval = setInterval(checkOfflineStatus, 2000);

    return () => {
      if (socket) {
        socket.off('system_telemetry', handleTelemetryData);
        socket.off('ips_mitigation');
      }
      clearInterval(offlineStatusInterval);
      disconnectSocket();
    };
  }, [offline]);

  useEffect(() => {
    let intervalId: NodeJS.Timeout | null = null;
    
    if (autoRefresh) {
      intervalId = setInterval(() => {
        handleRefresh();
      }, refreshInterval * 1000);
    }
    
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [autoRefresh, refreshInterval, offline]);

  // Calculate threat level based on system telemetry
  const calculateThreatLevel = (data: SystemTelemetryData) => {
    let level: 'low' | 'medium' | 'high' = 'low';
    
    // Check for high severity anomalies
    const highSeverityAnomalies = data.anomalies.filter(a => a.severity === 'high');
    if (highSeverityAnomalies.length > 0) {
      level = 'high';
    } 
    // Check for suspicious connections
    else if (data.networkConnections.some(conn => conn.suspicious)) {
      level = 'high';
    }
    // Check for medium severity anomalies
    else if (data.anomalies.filter(a => a.severity === 'medium').length > 0) {
      level = 'medium';
    }
    // Check for critical resource usage
    else if (data.memoryDetails.percent > 90 || data.cpuDetails.usage > 90) {
      level = 'medium';
    }
    
    setThreatLevel(level);
  };

  const handleRefresh = () => {
    if (offline) {
      // In offline mode, just update the mock data with new timestamps
      const mockData = getMockTelemetryData();
      setTelemetryData(mockData);
      setLastUpdate(new Date());
      
      // Generate security recommendations
      const recommendations = threatDetectionService.generateSecurityRecommendations(mockData);
      setSecurityRecommendations(recommendations);
      
      // Calculate threat level
      calculateThreatLevel(mockData);
      
      // toast.info('Refreshed threat intelligence data');
    } else {
      // toast.info('Refreshing system data...');
      const socket = getSocket();
      // In a real scenario this would trigger a refresh from the socket
      // For our mock implementation, the interval will pick up the next update
    }
  };

  const toggleAutoRefresh = () => {
    setAutoRefresh(!autoRefresh);
    toast(autoRefresh ? "Auto-refresh disabled" : "Auto-refresh enabled", {
      description: autoRefresh ? "Manual refresh only" : `Refreshing every ${refreshInterval} seconds`
    });
  };

  const setRefreshRate = (seconds: number) => {
    setRefreshInterval(seconds);
    if (autoRefresh) {
      toast.info(`Auto-refresh rate set to ${seconds} seconds`);
    }
  };

  const toggleOfflineMode = () => {
    if (offline) {
      disableOfflineMode();
    } else {
      enableOfflineMode();
    }
    setOffline(!offline);
  };
  
  const showSecurityRecommendations = () => {
    setSecurityDialogOpen(true);
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="px-6 py-4 border-b border-border/50 bg-cyber-black">
        <div className="flex flex-wrap justify-between items-center gap-3">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold">eCyber Intelligence</h1>
            {autoRefresh && !offline && (
              <span className="flex h-3 w-3">
                <span className="animate-ping absolute h-3 w-3 rounded-full bg-cyber-alert-green/50"></span>
                <span className="relative rounded-full h-3 w-3 bg-cyber-alert-green"></span>
              </span>
            )}
            {offline && (
              <span className="text-xs bg-amber-500/20 text-amber-500 px-2 py-0.5 rounded-full">Offline Mode</span>
            )}
            <span className={cn(
              "text-xs px-2 py-0.5 rounded-full ml-2",
              threatLevel === 'low' ? "bg-cyber-alert-green/20 text-cyber-alert-green" :
              threatLevel === 'medium' ? "bg-cyber-alert-amber/20 text-cyber-alert-amber" :
              "bg-cyber-alert-red/20 text-cyber-alert-red animate-pulse"
            )}>
              Threat Level: {threatLevel.toUpperCase()}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-sm text-muted-foreground">
              {lastUpdate ? (
                <span>Last updated: {lastUpdate.toLocaleTimeString()}</span>
              ) : (
                <span>Waiting for data...</span>
              )}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={toggleOfflineMode}
              className={cn(
                "flex items-center gap-1.5",
                offline && "border-amber-500 text-amber-500"
              )}
            >
              {offline ? (
                <>
                  <WifiOff className="h-3.5 w-3.5" />
                  <span>Offline</span>
                </>
              ) : (
                <>
                  <Wifi className="h-3.5 w-3.5" />
                  <span>Online</span>
                </>
              )}
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={showSecurityRecommendations}
              className="flex items-center gap-1.5"
            >
              <Shield className="h-3.5 w-3.5" />
              <span>Security</span>
              {securityRecommendations.some(r => r.status === 'critical') && (
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                </span>
              )}
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={toggleAutoRefresh}
              className={cn(
                "flex items-center gap-1",
                autoRefresh && "border-cyber-alert-green text-cyber-alert-green"
              )}
            >
              <span className={autoRefresh ? "text-cyber-alert-green" : ""}>
                {autoRefresh ? "Auto" : "Manual"}
              </span>
            </Button>
            
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  {refreshInterval}s
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={() => setRefreshRate(3)}>3s</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setRefreshRate(5)}>5s</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setRefreshRate(10)}>10s</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setRefreshRate(30)}>30s</DropdownMenuItem>
                <DropdownMenuItem onClick={() => setRefreshRate(60)}>60s</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleRefresh}
              className="flex items-center gap-1"
            >
              <RefreshCw className="h-4 w-4" />
              <span>Refresh</span>
            </Button>
          </div>
        </div>
      </header>
      
      <main className="p-6">
        {!telemetryData ? (
          <div className="flex justify-center items-center h-[500px]">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-chart-purple mx-auto mb-4"></div>
              <p className="text-muted-foreground">
                {offline 
                  ? "Loading offline monitoring data..." 
                  : "Connecting to system telemetry..."}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {/* System Overview Cards */}
            <div className="grid-auto-fit gap-4">
              {telemetryData.systemOverview.map((item, index) => (
                <StatusCard key={`${item.title}-${index}`} item={item} />
              ))}
            </div>
            
            {/* Threat Summary Card */}
            <Card className={cn(
              "border",
              threatLevel === 'low' ? "border-cyber-alert-green/50 bg-cyber-alert-green/5" :
              threatLevel === 'medium' ? "border-cyber-alert-amber/50 bg-cyber-alert-amber/5" :
              "border-cyber-alert-red/50 bg-cyber-alert-red/5 animate-pulse"
            )}>
              <CardHeader className="pb-2">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <AlertCircle className={cn(
                      "h-5 w-5",
                      threatLevel === 'low' ? "text-cyber-alert-green" :
                      threatLevel === 'medium' ? "text-cyber-alert-amber" :
                      "text-cyber-alert-red"
                    )} />
                    <CardTitle>Threat Intelligence Summary</CardTitle>
                  </div>
                  <span className={cn(
                    "text-xs px-3 py-1 rounded-full",
                    threatLevel === 'low' ? "bg-cyber-alert-green/20 text-cyber-alert-green" :
                    threatLevel === 'medium' ? "bg-cyber-alert-amber/20 text-cyber-alert-amber" :
                    "bg-cyber-alert-red/20 text-cyber-alert-red"
                  )}>
                    {threatLevel === 'low' && "No Significant Threats"}
                    {threatLevel === 'medium' && "Potential Threats Detected"}
                    {threatLevel === 'high' && "Critical Threats Detected"}
                  </span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="flex items-center gap-2 p-3 rounded-md bg-background">
                      <div className={cn(
                        "h-8 w-8 rounded-full flex items-center justify-center",
                        telemetryData.anomalies.length > 0 ? "bg-cyber-alert-red/20" : "bg-cyber-alert-green/20"
                      )}>
                        <span className={cn(
                          "font-bold",
                          telemetryData.anomalies.length > 0 ? "text-cyber-alert-red" : "text-cyber-alert-green"
                        )}>
                          {telemetryData.anomalies.length}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm font-medium">Anomalies Detected</p>
                        <p className="text-xs text-muted-foreground">
                          {telemetryData.anomalies.length === 0 ? "System normal" : "Requires attention"}
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 p-3 rounded-md bg-background">
                      <div className={cn(
                        "h-8 w-8 rounded-full flex items-center justify-center",
                        telemetryData.securityOverview.suspiciousConnections > 0 ? "bg-cyber-alert-red/20" : "bg-cyber-alert-green/20"
                      )}>
                        <span className={cn(
                          "font-bold",
                          telemetryData.securityOverview.suspiciousConnections > 0 ? "text-cyber-alert-red" : "text-cyber-alert-green"
                        )}>
                          {telemetryData.securityOverview.suspiciousConnections}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm font-medium">Suspicious Connections</p>
                        <p className="text-xs text-muted-foreground">
                          {telemetryData.securityOverview.suspiciousConnections === 0 ? "No suspicious traffic" : "Potential network threats"}
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 p-3 rounded-md bg-background">
                      <div className={cn(
                        "h-8 w-8 rounded-full flex items-center justify-center",
                        telemetryData.memoryDetails.percent > 85 ? "bg-cyber-alert-amber/20" : "bg-cyber-alert-green/20"
                      )}>
                        <span className={cn(
                          "font-bold",
                          telemetryData.memoryDetails.percent > 85 ? "text-cyber-alert-amber" : "text-cyber-alert-green"
                        )}>
                          {telemetryData.memoryDetails.percent}%
                        </span>
                      </div>
                      <div>
                        <p className="text-sm font-medium">Memory Usage</p>
                        <p className="text-xs text-muted-foreground">
                          {telemetryData.memoryDetails.percent > 85 ? "Critically high" : "Normal operations"}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  {threatLevel !== 'low' && (
                    <div className="mt-2 p-2 border border-dashed rounded border-amber-400/30 bg-amber-400/5">
                      <p className="text-sm text-amber-400">
                        <span className="font-medium">Security Alert: </span>
                        {threatLevel === 'medium' ? "Potential security issues detected. Review recommendations." : 
                                                   "Critical security threats detected! Immediate action required."}
                      </p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
            
            {/* Charts */}
            <Charts 
              cpuHistory={telemetryData.cpuHistory}
              memoryHistory={telemetryData.memoryHistory}
              networkIO={telemetryData.networkIO}
              diskIO={telemetryData.diskIO}
            />
            
            {/* Anomalies (always display panel, even if empty) */}
            <div id="anomalies-section">
              <AnomaliesPanel anomalies={telemetryData.anomalies} />
            </div>
            
            {/* Security Overview */}
            <SecurityOverview data={telemetryData.securityOverview} />
            
            {/* Process Monitor */}
            <ProcessMonitor processes={telemetryData.processes} />
            
            {/* Network Connections */}
            <NetworkConnections connections={telemetryData.networkConnections} />
            
            {/* Network Interfaces */}
            <NetworkInterfaces interfaces={telemetryData.networkInterfaces} />
          </div>
        )}
      </main>
      
      {/* Security Recommendations Dialog */}
      <Dialog open={securityDialogOpen} onOpenChange={setSecurityDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Security Recommendations</DialogTitle>
            <DialogDescription>
              Based on the current system state, the following security recommendations have been generated:
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4 space-y-4 max-h-[60vh] overflow-y-auto">
            {securityRecommendations.length === 0 ? (
              <p className="text-center text-muted-foreground py-8">
                No security recommendations at this time. System appears to be operating normally.
              </p>
            ) : (
              securityRecommendations.map((item, index) => (
                <div 
                  key={`${item.category}-${index}`}
                  className={cn(
                    "p-4 border rounded-lg",
                    item.status === "critical" ? "border-cyber-alert-red/50 bg-cyber-alert-red/5" :
                    item.status === "warning" ? "border-cyber-alert-amber/50 bg-cyber-alert-amber/5" :
                    "border-cyber-alert-blue/50 bg-cyber-alert-blue/5"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {item.status === "critical" && <AlertCircle className="h-5 w-5 text-cyber-alert-red" />}
                      {item.status === "warning" && <AlertCircle className="h-5 w-5 text-cyber-alert-amber" />}
                      {item.status === "info" && <AlertCircle className="h-5 w-5 text-cyber-alert-blue" />}
                      <h4 className="font-semibold">{item.category}</h4>
                    </div>
                    <span className={cn(
                      "text-xs px-2 py-0.5 rounded-full",
                      item.status === "critical" ? "bg-cyber-alert-red/20 text-cyber-alert-red" :
                      item.status === "warning" ? "bg-cyber-alert-amber/20 text-cyber-alert-amber" :
                      "bg-cyber-alert-blue/20 text-cyber-alert-blue"
                    )}>
                      {item.status.toUpperCase()}
                    </span>
                  </div>
                  
                  <p className="mt-2 text-sm">{item.description}</p>
                  
                  {item.recommendations && (
                    <div className="mt-3">
                      <p className="text-xs font-semibold text-muted-foreground mb-1">RECOMMENDATIONS:</p>
                      <ul className="text-sm space-y-1">
                        {item.recommendations.map((rec, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="text-cyber-alert-green">•</span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setSecurityDialogOpen(false)}>
              Close
            </Button>
            {securityRecommendations.length > 0 && (
              <Button variant="default" onClick={() => {
                toast.success("Security report generated", {
                  description: "Full security report has been saved to your downloads folder"
                });
                setSecurityDialogOpen(false);
              }}>
                Generate Report
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
