import React from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Globe, ArrowRight, Activity, WifiOff } from 'lucide-react';
import Header from '../components/layout/Header';
import InteractiveNetworkMap from '../components/network/InteractiveNetworkMap';

// Sample network data
const networkDevices = [
  { id: 1, name: "Core Router", ip: "10.0.0.1", status: "online", traffic: "1.2 GB/s", connections: 124 },
  { id: 2, name: "Firewall", ip: "10.0.0.2", status: "online", traffic: "840 MB/s", connections: 78 },
  { id: 3, name: "Web Server", ip: "10.0.1.10", status: "online", traffic: "320 MB/s", connections: 45 },
  { id: 4, name: "Database Server", ip: "10.0.1.11", status: "warning", traffic: "150 MB/s", connections: 12 },
  { id: 5, name: "Storage Server", ip: "10.0.1.12", status: "online", traffic: "230 MB/s", connections: 8 },
  { id: 6, name: "Backup Server", ip: "10.0.1.13", status: "offline", traffic: "0 KB/s", connections: 0 },
];

const recentConnections = [
  { source: "10.0.1.45", destination: "185.93.2.41", protocol: "HTTPS", status: "blocked", timestamp: new Date(Date.now() - 5 * 60 * 1000) },
  { source: "10.0.1.12", destination: "10.0.1.10", protocol: "SQL", status: "allowed", timestamp: new Date(Date.now() - 8 * 60 * 1000) },
  { source: "10.0.2.31", destination: "103.56.112.8", protocol: "SSH", status: "blocked", timestamp: new Date(Date.now() - 15 * 60 * 1000) },
  { source: "10.0.1.25", destination: "10.0.1.11", protocol: "HTTP", status: "allowed", timestamp: new Date(Date.now() - 23 * 60 * 1000) },
];

const Network = () => {
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Network Map</h1>
              <p className="text-muted-foreground">Visualize and monitor network traffic</p>
            </div>
            
            <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
          
          {/* Interactive Network Map */}
          <div className="mb-6">
            <InteractiveNetworkMap />
          </div>
          
          {/* Network stats and devices */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            {/* Traffic stats */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center">
                  <Activity className="mr-2" size={16} />
                  Traffic Statistics
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Inbound Traffic</span>
                      <span className="text-sm font-medium">840 MB/s</span>
                    </div>
                    <div className="w-full h-2 bg-muted mt-1 rounded-full">
                      <div className="bg-blue-500 h-full rounded-full" style={{ width: "60%" }}></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Outbound Traffic</span>
                      <span className="text-sm font-medium">620 MB/s</span>
                    </div>
                    <div className="w-full h-2 bg-muted mt-1 rounded-full">
                      <div className="bg-green-500 h-full rounded-full" style={{ width: "45%" }}></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Active Connections</span>
                      <span className="text-sm font-medium">267</span>
                    </div>
                    <div className="w-full h-2 bg-muted mt-1 rounded-full">
                      <div className="bg-amber-500 h-full rounded-full" style={{ width: "35%" }}></div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            {/* Network devices */}
            <Card className="col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center justify-between">
                  <span>Network Devices</span>
                  <Badge className="ml-2">{networkDevices.length}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {networkDevices.map((device) => (
                    <div key={device.id} className="flex items-center justify-between p-3 border border-border rounded-md">
                      <div>
                        <div className="flex items-center">
                          <div className={cn(
                            "w-2 h-2 rounded-full mr-2",
                            device.status === "online" ? "bg-green-500" : 
                            device.status === "warning" ? "bg-amber-500" : "bg-red-500"
                          )}></div>
                          <span className="font-medium">{device.name}</span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">{device.ip}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm">{device.connections} connections</div>
                        <div className="text-xs text-muted-foreground">{device.traffic}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" size="sm" className="ml-auto">
                  View All Devices <ArrowRight className="ml-1" size={12} />
                </Button>
              </CardFooter>
            </Card>
          </div>
          
          {/* Recent connections */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center">
                <WifiOff className="mr-2" size={16} />
                Recent Connection Events
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="border border-border rounded-md overflow-hidden">
                <div className="grid grid-cols-12 gap-4 p-3 bg-muted text-xs font-medium">
                  <div className="col-span-3">Source</div>
                  <div className="col-span-3">Destination</div>
                  <div className="col-span-2">Protocol</div>
                  <div className="col-span-2">Status</div>
                  <div className="col-span-2">Time</div>
                </div>
                <div className="divide-y divide-border">
                  {recentConnections.map((connection, i) => (
                    <div key={i} className="grid grid-cols-12 gap-4 p-3 text-xs">
                      <div className="col-span-3 font-mono">{connection.source}</div>
                      <div className="col-span-3 font-mono">{connection.destination}</div>
                      <div className="col-span-2">{connection.protocol}</div>
                      <div className="col-span-2">
                        <Badge variant="outline" className={cn(
                          connection.status === "allowed" ? "bg-green-500/10 text-green-500" : 
                          "bg-red-500/10 text-red-500"
                        )}>
                          {connection.status}
                        </Badge>
                      </div>
                      <div className="col-span-2 text-muted-foreground">
                        {connection.timestamp.toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <Button variant="ghost" size="sm" className="ml-auto">
                View All Connections <ArrowRight className="ml-1" size={12} />
              </Button>
            </CardFooter>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Network;