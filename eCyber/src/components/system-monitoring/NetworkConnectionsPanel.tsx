
import React, { useState, useEffect } from 'react';
import { 
  Globe, Database, Search, Filter, AlertTriangle, 
  MapPin, RefreshCcw, Shield
} from 'lucide-react';
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

// Types for network connection
interface NetworkConnection {
  id: string;
  localIP: string;
  remoteIP: string;
  port: number;
  protocol: 'TCP' | 'UDP';
  state: string;
  process: string;
  country?: string;
  city?: string;
  isSuspicious: boolean;
}

const NetworkConnectionsPanel = () => {
  const { toast } = useToast();
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);
  
  // Generate sample network connections
  const generateNetworkConnections = () => {
    const protocols: ('TCP' | 'UDP')[] = ['TCP', 'UDP'];
    const states = ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT'];
    const processes = ['nginx', 'sshd', 'mysql', 'node', 'python3', 'apache2', 'postgres'];
    const countries = ['United States', 'Germany', 'China', 'Russia', 'Brazil', 'India', 'Japan'];
    const remoteIPs = [
      '192.168.1.1',
      '10.0.0.25',
      '172.16.254.1',
      '54.239.28.85',
      '157.240.22.35',
      '104.244.42.65',
      '34.102.136.180',
      '209.85.167.188'
    ];
    
    const connectionsCount = Math.floor(Math.random() * 8) + 5; // 5-12 connections
    const connections: NetworkConnection[] = [];
    
    for (let i = 0; i < connectionsCount; i++) {
      const protocol = protocols[Math.floor(Math.random() * protocols.length)];
      const state = states[Math.floor(Math.random() * states.length)];
      const process = processes[Math.floor(Math.random() * processes.length)];
      const country = countries[Math.floor(Math.random() * countries.length)];
      const remoteIP = remoteIPs[Math.floor(Math.random() * remoteIPs.length)];
      const port = Math.floor(Math.random() * 60000) + 1024; // Random port between 1024-65535
      const isSuspicious = Math.random() > 0.9; // 10% chance of being suspicious
      
      connections.push({
        id: `conn-${Date.now()}-${i}`,
        localIP: '192.168.1.' + (Math.floor(Math.random() * 254) + 1),
        remoteIP,
        port,
        protocol,
        state,
        process,
        country,
        city: 'Unknown',
        isSuspicious
      });
    }
    
    return connections;
  };
  
  // Initialize and refresh network connections
  useEffect(() => {
    const connections = generateNetworkConnections();
    setConnections(connections);
    
    const interval = setInterval(() => {
      const newConnections = generateNetworkConnections();
      setConnections(newConnections);
      
      // Show toast for suspicious connections
      const suspiciousConnections = newConnections.filter(conn => conn.isSuspicious);
      if (suspiciousConnections.length > 0) {
        toast({
          title: "Suspicious Connection Detected",
          description: `Connection to ${suspiciousConnections[0].remoteIP} from process ${suspiciousConnections[0].process}`,
          variant: "destructive"
        });
      }
    }, 10000); // Refresh every 10 seconds
    
    return () => clearInterval(interval);
  }, [toast]);
  
  // Filter connections based on search term and suspicious flag
  const filteredConnections = connections.filter(conn => {
    const matchesSearch = !searchTerm || 
      conn.remoteIP.includes(searchTerm) || 
      conn.localIP.includes(searchTerm) || 
      conn.process.includes(searchTerm) ||
      (conn.country && conn.country.toLowerCase().includes(searchTerm.toLowerCase()));
    
    return matchesSearch && (!showSuspiciousOnly || conn.isSuspicious);
  });
  
  // Block IP address
  const blockIP = (ip: string) => {
    toast({
      title: "IP Blocked",
      description: `Connection to ${ip} has been blocked`,
    });
    
    // In a real implementation, this would call an API to block the IP
  };
  
  // Trace route to IP
  const traceRoute = (ip: string) => {
    toast({
      title: "Trace Route Initiated",
      description: `Tracing route to ${ip}...`,
    });
    
    // In a real implementation, this would call an API to trace the route
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Network Connections</h3>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search connections..."
              className="pl-8 h-9 w-[250px] rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Button 
            size="sm" 
            variant={showSuspiciousOnly ? "default" : "outline"} 
            className="h-9 gap-1"
            onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
          >
            <AlertTriangle className="h-4 w-4" />
            {showSuspiciousOnly ? "All Connections" : "Suspicious Only"}
          </Button>
          <Button 
            size="sm" 
            className="h-9 gap-1"
            onClick={() => setConnections(generateNetworkConnections())}
          >
            <RefreshCcw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>
      
      {/* Network Map (placeholder) */}
      <div className="border rounded-lg p-4">
        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
          <Globe className="h-4 w-4" />
          GeoIP Connection Map
        </h4>
        <div className="bg-muted h-[200px] rounded-md flex items-center justify-center">
          <span className="text-muted-foreground">World map with connection lines would appear here</span>
        </div>
      </div>
      
      {/* Network Connections Table */}
      <div className="border rounded-lg overflow-hidden">
        <div className="grid grid-cols-8 gap-2 py-2 px-3 bg-muted text-xs font-medium">
          <div className="col-span-1">Process</div>
          <div className="col-span-1">Protocol</div>
          <div className="col-span-1">Local IP</div>
          <div className="col-span-2">Remote IP</div>
          <div className="col-span-1">Port</div>
          <div className="col-span-1">State</div>
          <div className="col-span-1">Actions</div>
        </div>
        
        <ScrollArea className="h-[400px]">
          {filteredConnections.length > 0 ? (
            <div className="divide-y">
              {filteredConnections.map((conn) => (
                <div 
                  key={conn.id}
                  className={`grid grid-cols-8 gap-2 py-2 px-3 text-xs ${
                    conn.isSuspicious ? 'bg-red-500/5' : ''
                  } hover:bg-muted/50`}
                >
                  <div className="col-span-1 flex items-center">
                    <span className={conn.isSuspicious ? 'font-medium text-red-500' : ''}>
                      {conn.process}
                    </span>
                  </div>
                  <div className="col-span-1">
                    <Badge variant="outline">
                      {conn.protocol}
                    </Badge>
                  </div>
                  <div className="col-span-1 font-mono">
                    {conn.localIP}
                  </div>
                  <div className="col-span-2 font-mono flex items-center gap-1">
                    {conn.isSuspicious && <AlertTriangle className="h-3 w-3 text-red-500" />}
                    {conn.remoteIP}
                    <span className="text-xs text-muted-foreground ml-1">
                      ({conn.country})
                    </span>
                  </div>
                  <div className="col-span-1 font-mono">
                    {conn.port}
                  </div>
                  <div className="col-span-1">
                    <Badge variant={conn.state === 'ESTABLISHED' ? 'default' : 'secondary'} className="text-[10px]">
                      {conn.state}
                    </Badge>
                  </div>
                  <div className="col-span-1 flex items-center gap-1">
                    <Button 
                      variant={conn.isSuspicious ? "destructive" : "ghost"} 
                      size="sm" 
                      className="h-6 text-[10px]"
                      onClick={() => blockIP(conn.remoteIP)}
                    >
                      <Shield className="h-3 w-3 mr-1" />
                      Block
                    </Button>
                    <Button 
                      variant="ghost"
                      size="sm" 
                      className="h-6 text-[10px]"
                      onClick={() => traceRoute(conn.remoteIP)}
                    >
                      <MapPin className="h-3 w-3 mr-1" />
                      Trace
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No network connections matching your criteria
            </div>
          )}
        </ScrollArea>
      </div>
      
      {/* Connection Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Total Connections</div>
          <div className="text-2xl font-bold">{connections.length}</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Established</div>
          <div className="text-2xl font-bold">{connections.filter(c => c.state === 'ESTABLISHED').length}</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Suspicious</div>
          <div className="text-2xl font-bold text-red-500">{connections.filter(c => c.isSuspicious).length}</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Countries</div>
          <div className="text-2xl font-bold">{new Set(connections.map(c => c.country)).size}</div>
        </div>
      </div>
    </div>
  );
};

export default NetworkConnectionsPanel;
