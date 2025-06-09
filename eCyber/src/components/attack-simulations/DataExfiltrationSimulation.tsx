
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Database, AlertTriangle, FileCode, ArrowUpFromLine, Globe, Play, Loader2, FileBarChart } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// Network request interface
interface NetworkRequest {
  id: string;
  timestamp: Date;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  bytes_sent: number;
  file_type: string | null;
  is_suspicious: boolean;
  status: 'completed' | 'blocked' | 'in_progress';
}

// File type interface
interface FileType {
  name: string;
  size: number;
  sensitivity: 'low' | 'medium' | 'high';
  extension: string;
}

const DataExfiltrationSimulation = () => {
  const { toast } = useToast();
  const [isSimulating, setIsSimulating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [networkRequests, setNetworkRequests] = useState<NetworkRequest[]>([]);
  const [dataSensitivity, setDataSensitivity] = useState<Record<string, number>>({
    'low': 0,
    'medium': 0,
    'high': 0
  });
  const [totalDataExfiltrated, setTotalDataExfiltrated] = useState(0);
  const [activeTab, setActiveTab] = useState('traffic');

  // File types for simulation
  const fileTypes: FileType[] = [
    { name: 'Customer Database', size: 15400000, sensitivity: 'high', extension: '.sql' },
    { name: 'Financial Records', size: 8700000, sensitivity: 'high', extension: '.xlsx' },
    { name: 'Employee Data', size: 4200000, sensitivity: 'high', extension: '.csv' },
    { name: 'Product Catalog', size: 9800000, sensitivity: 'medium', extension: '.json' },
    { name: 'Source Code', size: 21500000, sensitivity: 'medium', extension: '.zip' },
    { name: 'Marketing Plan', size: 3100000, sensitivity: 'medium', extension: '.pptx' },
    { name: 'Public Images', size: 18900000, sensitivity: 'low', extension: '.zip' },
    { name: 'Public Documents', size: 5600000, sensitivity: 'low', extension: '.pdf' }
  ];
  
  // Generate a random destination
  const generateDestination = (suspicious = false) => {
    if (suspicious) {
      const suspiciousDestinations = [
        { ip: '185.212.47.39', port: 443, country: 'Russia' },
        { ip: '103.48.52.198', port: 22, country: 'China' },
        { ip: '91.243.85.72', port: 21, country: 'Ukraine' },
        { ip: '45.137.21.9', port: 443, country: 'Romania' }
      ];
      return suspiciousDestinations[Math.floor(Math.random() * suspiciousDestinations.length)];
    } else {
      const normalDestinations = [
        { ip: '151.101.1.208', port: 443, country: 'United States (Cloudflare)' }, // Cloudflare
        { ip: '13.107.42.22', port: 443, country: 'United States (Microsoft)' },   // Microsoft
        { ip: '172.217.3.110', port: 443, country: 'United States (Google)' },     // Google
        { ip: '52.216.109.171', port: 443, country: 'United States (Amazon)' }     // AWS
      ];
      return normalDestinations[Math.floor(Math.random() * normalDestinations.length)];
    }
  };
  
  // Format bytes into KB, MB, GB
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) {
      return bytes + ' B';
    } else if (bytes < 1024 * 1024) {
      return (bytes / 1024).toFixed(2) + ' KB';
    } else if (bytes < 1024 * 1024 * 1024) {
      return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    } else {
      return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }
  };
  
  // Start simulation
  const startSimulation = () => {
    setIsSimulating(true);
    setProgress(0);
    setNetworkRequests([]);
    setTotalDataExfiltrated(0);
    setDataSensitivity({ 'low': 0, 'medium': 0, 'high': 0 });
    
    // Show starting toast
    toast({
      title: "Data Exfiltration Simulation Started",
      description: "Monitoring network traffic for suspicious data transfers",
      variant: "default"
    });
    
    // Simulate normal traffic first
    simulateNormalTraffic();
  };
  
  // Simulate normal traffic
  const simulateNormalTraffic = () => {
    const interval = setInterval(() => {
      const destination = generateDestination();
      
      // Create normal request
      const newRequest: NetworkRequest = {
        id: `req-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        timestamp: new Date(),
        source_ip: '192.168.1.' + Math.floor(Math.random() * 100 + 10),
        destination_ip: destination.ip,
        destination_port: destination.port,
        protocol: Math.random() > 0.5 ? 'HTTPS' : 'HTTP',
        bytes_sent: Math.floor(Math.random() * 100000),
        file_type: null,
        is_suspicious: false,
        status: 'completed'
      };
      
      // Add request to list
      setNetworkRequests(prev => {
        if (prev.length > 20) {
          return [...prev.slice(1), newRequest]; // Keep only last 20 requests
        } else {
          return [...prev, newRequest];
        }
      });
      
      // Update progress
      setProgress(prev => {
        const newProgress = prev + 5;
        if (newProgress >= 30) {
          clearInterval(interval);
          simulateDataExfiltration();
        }
        return newProgress;
      });
      
    }, 800);
    
    return () => clearInterval(interval);
  };
  
  // Simulate data exfiltration
  const simulateDataExfiltration = () => {
    // Start suspicious activity
    let exfilCount = 0;
    const maxExfil = 5;
    
    const interval = setInterval(() => {
      const destination = generateDestination(true);
      const isSuspicious = true;
      const fileType = fileTypes[Math.floor(Math.random() * fileTypes.length)];
      
      // Create suspicious request
      const newRequest: NetworkRequest = {
        id: `req-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        timestamp: new Date(),
        source_ip: '192.168.1.' + Math.floor(Math.random() * 10 + 20),
        destination_ip: destination.ip,
        destination_port: destination.port,
        protocol: 'HTTPS',
        bytes_sent: fileType.size,
        file_type: `${fileType.name}${fileType.extension}`,
        is_suspicious: isSuspicious,
        status: 'completed'
      };
      
      // Update data sensitivity metrics
      setDataSensitivity(prev => ({
        ...prev,
        [fileType.sensitivity]: prev[fileType.sensitivity] + fileType.size
      }));
      
      // Update total data exfiltrated
      setTotalDataExfiltrated(prev => prev + fileType.size);
      
      // Add request to list
      setNetworkRequests(prev => {
        if (prev.length > 20) {
          return [...prev.slice(1), newRequest]; // Keep only last 20 requests
        } else {
          return [...prev, newRequest];
        }
      });
      
      // Show alert for high sensitivity data
      if (fileType.sensitivity === 'high') {
        toast({
          title: "Critical Alert: Sensitive Data Exfiltration",
          description: `${fileType.name} (${formatBytes(fileType.size)}) sent to ${destination.ip} (${destination.country})`,
          variant: "destructive"
        });
      }
      
      // Update progress
      exfilCount++;
      setProgress(30 + (exfilCount / maxExfil * 70));
      
      if (exfilCount >= maxExfil) {
        clearInterval(interval);
        setIsSimulating(false);
        
        // Show completion toast
        toast({
          title: "Data Exfiltration Simulation Complete",
          description: `${formatBytes(totalDataExfiltrated)} of data exfiltrated in simulation`,
          variant: "default"
        });
      }
      
    }, 2000);
    
    return () => clearInterval(interval);
  };
  
  // Get background color based on sensitivity
  const getSensitivityColor = (sensitivity: 'low' | 'medium' | 'high' | null) => {
    if (!sensitivity) return '';
    
    switch (sensitivity) {
      case 'high':
        return 'bg-red-500/10 text-red-500 border-red-500/30';
      case 'medium':
        return 'bg-amber-500/10 text-amber-500 border-amber-500/30';
      case 'low':
        return 'bg-green-500/10 text-green-500 border-green-500/30';
      default:
        return '';
    }
  };
  
  // Get sensitivity level from file type
  const getSensitivityLevel = (fileName: string | null): 'low' | 'medium' | 'high' | null => {
    if (!fileName) return null;
    
    const fileType = fileTypes.find(ft => fileName.includes(ft.name));
    return fileType?.sensitivity || null;
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5 text-isimbi-purple" />
              Data Exfiltration
            </CardTitle>
            <CardDescription>Monitor and detect unusual outbound data transfers</CardDescription>
          </div>
          <Badge variant={isSimulating ? "destructive" : "outline"} className="ml-2">
            {isSimulating ? "ACTIVE" : "Ready"}
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-6">
        {/* Progress indicator during simulation */}
        {isSimulating && (
          <div className="mb-4">
            <div className="flex justify-between text-sm mb-1">
              <span>Simulation Progress</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>
        )}
        
        <Tabs defaultValue="traffic" onValueChange={setActiveTab}>
          <TabsList className="mb-4">
            <TabsTrigger value="traffic">Network Traffic</TabsTrigger>
            <TabsTrigger value="data">Data Analysis</TabsTrigger>
          </TabsList>
          
          <TabsContent value="traffic">
            <div className="border rounded-lg">
              <div className="bg-muted p-2 grid grid-cols-7 gap-2 text-xs font-medium">
                <div className="col-span-1">Time</div>
                <div className="col-span-1">Source</div>
                <div className="col-span-1">Destination</div>
                <div className="col-span-1">Protocol</div>
                <div className="col-span-1">Size</div>
                <div className="col-span-2">File</div>
              </div>
              
              <ScrollArea className="h-[300px]">
                {networkRequests.length > 0 ? (
                  <div className="divide-y">
                    {networkRequests.map(request => (
                      <div 
                        key={request.id} 
                        className={`grid grid-cols-7 gap-2 p-2 text-xs ${
                          request.is_suspicious ? 'bg-red-500/5' : ''
                        } hover:bg-muted/50`}
                      >
                        <div className="col-span-1">
                          {request.timestamp.toLocaleTimeString()}
                        </div>
                        <div className="col-span-1 font-mono">
                          {request.source_ip}
                        </div>
                        <div className="col-span-1 font-mono">
                          {request.destination_ip}:{request.destination_port}
                        </div>
                        <div className="col-span-1">
                          {request.protocol}
                        </div>
                        <div className="col-span-1">
                          {formatBytes(request.bytes_sent)}
                        </div>
                        <div className="col-span-2">
                          {request.file_type && (
                            <span className={`text-xs px-1.5 py-0.5 rounded ${
                              getSensitivityColor(getSensitivityLevel(request.file_type))
                            }`}>
                              {request.file_type}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-[300px] text-center text-muted-foreground">
                    <Globe className="h-12 w-12 mb-2 opacity-30" />
                    <p>Start simulation to monitor network traffic</p>
                  </div>
                )}
              </ScrollArea>
            </div>
          </TabsContent>
          
          <TabsContent value="data">
            <div className="space-y-4">
              {/* Data exfiltration metrics */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="border rounded-lg p-3">
                  <div className="text-xs text-muted-foreground mb-1">Low Sensitivity Data</div>
                  <div className="flex justify-between items-center">
                    <FileBarChart className="h-4 w-4 text-green-500" />
                    <div className="text-xl font-medium text-green-500">
                      {formatBytes(dataSensitivity.low)}
                    </div>
                  </div>
                  <Progress value={dataSensitivity.low > 0 ? 100 : 0} className="h-1 mt-2 bg-green-500/20 text-green-500" />
                </div>
                
                <div className="border rounded-lg p-3">
                  <div className="text-xs text-muted-foreground mb-1">Medium Sensitivity Data</div>
                  <div className="flex justify-between items-center">
                    <FileBarChart className="h-4 w-4 text-amber-500" />
                    <div className="text-xl font-medium text-amber-500">
                      {formatBytes(dataSensitivity.medium)}
                    </div>
                  </div>
                  <Progress value={dataSensitivity.medium > 0 ? 100 : 0} className="h-1 mt-2 bg-amber-500/20 text-amber-500" />
                </div>
                
                <div className="border rounded-lg p-3">
                  <div className="text-xs text-muted-foreground mb-1">High Sensitivity Data</div>
                  <div className="flex justify-between items-center">
                    <FileBarChart className="h-4 w-4 text-red-500" />
                    <div className="text-xl font-medium text-red-500">
                      {formatBytes(dataSensitivity.high)}
                    </div>
                  </div>
                  <Progress value={dataSensitivity.high > 0 ? 100 : 0} className="h-1 mt-2 bg-red-500/20 text-red-500" />
                </div>
              </div>
              
              {/* Total exfiltrated data */}
              {totalDataExfiltrated > 0 && (
                <div className="border rounded-lg p-4 bg-muted/30">
                  <div className="flex justify-between items-center">
                    <div>
                      <h3 className="text-sm font-medium">Total Data Exfiltrated</h3>
                      <p className="text-xs text-muted-foreground mt-1">
                        {networkRequests.filter(r => r.is_suspicious).length} suspicious transfers detected
                      </p>
                    </div>
                    <div className="text-xl font-bold">
                      {formatBytes(totalDataExfiltrated)}
                    </div>
                  </div>
                </div>
              )}
              
              {/* Recommendations */}
              {totalDataExfiltrated > 0 && (
                <div className="p-3 border rounded-lg bg-red-500/5 border-red-500/30">
                  <h3 className="text-sm font-medium mb-2 text-red-500 flex items-center">
                    <AlertTriangle size={16} className="mr-2" />
                    Security Recommendations
                  </h3>
                  <ul className="space-y-1 text-sm">
                    <li className="flex items-start">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-500 mr-2 mt-1.5"></span>
                      <span>Implement Data Loss Prevention (DLP) controls to monitor sensitive data transfers</span>
                    </li>
                    <li className="flex items-start">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-500 mr-2 mt-1.5"></span>
                      <span>Configure firewall rules to block outbound connections to suspicious countries</span>
                    </li>
                    <li className="flex items-start">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-500 mr-2 mt-1.5"></span>
                      <span>Encrypt sensitive data at rest to prevent unauthorized access</span>
                    </li>
                  </ul>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        <div className="text-xs text-muted-foreground">
          {networkRequests.filter(r => r.is_suspicious).length > 0 
            ? `${networkRequests.filter(r => r.is_suspicious).length} suspicious transfers detected` 
            : "No data exfiltration detected"}
        </div>
        <Button 
          onClick={startSimulation} 
          disabled={isSimulating}
          className="gap-2"
        >
          {isSimulating ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Simulating...
            </>
          ) : (
            <>
              <ArrowUpFromLine className="h-4 w-4" />
              Simulate Transfer
            </>
          )}
        </Button>
      </CardFooter>
    </Card>
  );
};

export default DataExfiltrationSimulation;
