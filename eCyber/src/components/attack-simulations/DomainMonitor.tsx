
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Globe, AlertCircle, Clock, Plus, ExternalLink, Search, Loader2, RefreshCw } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

// Types for domain monitoring
interface MonitoredDomain {
  id: string;
  domain: string;
  status: 'active' | 'warning' | 'critical' | 'expired';
  lastCheck: Date;
  expiryDate: Date;
  daysToExpiry: number;
  issuer?: string;
  ipAddresses: string[];
  lookupCount: number;
  registrar?: string;
}

interface DomainActivity {
  id: string;
  domain: string;
  timestamp: Date;
  activityType: 'lookup' | 'expiry-warning' | 'certificate-change' | 'registrar-change' | 'ip-change' | 'added' | 'expired';
  details: string;
  importance: 'low' | 'medium' | 'high';
}

const DomainMonitor = () => {
  const { toast } = useToast();
  const [monitoredDomains, setMonitoredDomains] = useState<MonitoredDomain[]>([]);
  const [domainActivities, setDomainActivities] = useState<DomainActivity[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [isAddingDomain, setIsAddingDomain] = useState(false);
  const [isChecking, setIsChecking] = useState(false);
  const [activeTab, setActiveTab] = useState('domains');
  const [selectedDomain, setSelectedDomain] = useState<MonitoredDomain | null>(null);
  
  // Sample data for simulation
  useEffect(() => {
    // Generate sample monitored domains
    const domains = [
      {
        id: 'dom-1',
        domain: 'example.com',
        status: 'active',
        lastCheck: new Date(Date.now() - 2 * 60 * 60 * 1000),
        expiryDate: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
        daysToExpiry: 180,
        issuer: 'Let\'s Encrypt',
        ipAddresses: ['104.21.6.189', '172.67.174.56'],
        lookupCount: 12,
        registrar: 'GoDaddy'
      },
      {
        id: 'dom-2',
        domain: 'securebank.example',
        status: 'warning',
        lastCheck: new Date(Date.now() - 4 * 60 * 60 * 1000),
        expiryDate: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000),
        daysToExpiry: 20,
        issuer: 'DigiCert Inc',
        ipAddresses: ['198.51.100.73'],
        lookupCount: 45,
        registrar: 'Namecheap'
      },
      {
        id: 'dom-3',
        domain: 'cloudservice.example',
        status: 'active',
        lastCheck: new Date(Date.now() - 1 * 60 * 60 * 1000),
        expiryDate: new Date(Date.now() + 280 * 24 * 60 * 60 * 1000),
        daysToExpiry: 280,
        issuer: 'Amazon',
        ipAddresses: ['203.0.113.42', '203.0.113.43'],
        lookupCount: 8,
        registrar: 'Amazon Registrar'
      },
      {
        id: 'dom-4',
        domain: 'critical-service.example',
        status: 'critical',
        lastCheck: new Date(Date.now() - 0.5 * 60 * 60 * 1000),
        expiryDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
        daysToExpiry: 5,
        issuer: 'GeoTrust',
        ipAddresses: ['192.0.2.146'],
        lookupCount: 32,
        registrar: 'Network Solutions'
      },
      {
        id: 'dom-5',
        domain: 'expired-service.example',
        status: 'expired',
        lastCheck: new Date(Date.now() - 12 * 60 * 60 * 1000),
        expiryDate: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        daysToExpiry: -2,
        issuer: 'Sectigo',
        ipAddresses: ['198.51.100.28'],
        lookupCount: 5,
        registrar: 'Tucows'
      }
    ] as MonitoredDomain[];
    
    setMonitoredDomains(domains);
    
    // Generate sample activities
    const activities = [
      {
        id: 'act-1',
        domain: 'securebank.example',
        timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000),
        activityType: 'expiry-warning',
        details: 'Certificate expires in 20 days',
        importance: 'high'
      },
      {
        id: 'act-2',
        domain: 'example.com',
        timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000),
        activityType: 'lookup',
        details: 'Unusual number of DNS lookups detected',
        importance: 'medium'
      },
      {
        id: 'act-3',
        domain: 'critical-service.example',
        timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000),
        activityType: 'expiry-warning',
        details: 'Certificate expires in 5 days',
        importance: 'high'
      },
      {
        id: 'act-4',
        domain: 'cloudservice.example',
        timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000),
        activityType: 'ip-change',
        details: 'IP address changed from 203.0.113.40 to 203.0.113.42',
        importance: 'medium'
      },
      {
        id: 'act-5',
        domain: 'expired-service.example',
        timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        activityType: 'expired',
        details: 'SSL certificate has expired',
        importance: 'high'
      },
      {
        id: 'act-6',
        domain: 'example.com',
        timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        activityType: 'registrar-change',
        details: 'Domain registrar changed from "NameCheap" to "GoDaddy"',
        importance: 'medium'
      }
    ] as DomainActivity[];
    
    setDomainActivities(activities);
  }, []);
  
  // Simulate adding a new domain
  const addDomain = () => {
    if (!newDomain) {
      toast({
        title: "Invalid Domain",
        description: "Please enter a valid domain name",
        variant: "destructive"
      });
      return;
    }
    
    setIsAddingDomain(true);
    
    // Simulate API call delay
    setTimeout(() => {
      // Create a new domain monitoring entry
      const today = new Date();
      const randomDaysToExpiry = Math.floor(Math.random() * 300) + 30;
      const expiryDate = new Date();
      expiryDate.setDate(today.getDate() + randomDaysToExpiry);
      
      const newDomainEntry: MonitoredDomain = {
        id: `dom-${Date.now()}`,
        domain: newDomain,
        status: randomDaysToExpiry < 30 ? 'warning' : 'active',
        lastCheck: new Date(),
        expiryDate,
        daysToExpiry: randomDaysToExpiry,
        issuer: 'Let\'s Encrypt',
        ipAddresses: [`192.0.2.${Math.floor(Math.random() * 254) + 1}`],
        lookupCount: 0,
        registrar: 'Unknown'
      };
      
      // Add to monitored domains
      setMonitoredDomains(prev => [newDomainEntry, ...prev]);
      
      // Create activity for domain addition
      const newActivity: DomainActivity = {
        id: `act-${Date.now()}`,
        domain: newDomain,
        timestamp: new Date(),
        activityType: 'added',
        details: `Domain ${newDomain} added to monitoring`,
        importance: 'low'
      };
      
      setDomainActivities(prev => [newActivity, ...prev]);
      
      // Reset form
      setNewDomain('');
      setIsAddingDomain(false);
      
      toast({
        title: "Domain Added",
        description: `${newDomain} has been added to monitoring`,
        variant: "default"
      });
    }, 1500);
  };
  
  // Check domain certificates
  const checkDomainCertificates = () => {
    setIsChecking(true);
    
    // Simulate API call delay
    setTimeout(() => {
      // Update last check time for all domains
      const updatedDomains = monitoredDomains.map(domain => ({
        ...domain,
        lastCheck: new Date()
      }));
      
      setMonitoredDomains(updatedDomains);
      setIsChecking(false);
      
      toast({
        title: "Domain Check Complete",
        description: `${monitoredDomains.length} domains checked successfully`,
        variant: "default"
      });
    }, 2000);
  };
  
  // Get status badge
  const getStatusBadge = (status: 'active' | 'warning' | 'critical' | 'expired') => {
    switch (status) {
      case 'active':
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">Active</Badge>;
      case 'warning':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Warning</Badge>;
      case 'critical':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Critical</Badge>;
      case 'expired':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Expired</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };
  
  // Get activity importance badge
  const getImportanceBadge = (importance: 'low' | 'medium' | 'high') => {
    switch (importance) {
      case 'low':
        return <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500">Low</Badge>;
      case 'medium':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Medium</Badge>;
      case 'high':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">High</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };
  
  // Get activity icon
  const getActivityIcon = (activityType: string) => {
    switch (activityType) {
      case 'lookup':
        return <Search className="h-4 w-4 text-blue-500" />;
      case 'expiry-warning':
        return <Clock className="h-4 w-4 text-amber-500" />;
      case 'certificate-change':
        return <RefreshCw className="h-4 w-4 text-purple-500" />;
      case 'registrar-change':
        return <AlertCircle className="h-4 w-4 text-blue-500" />;
      case 'ip-change':
        return <Globe className="h-4 w-4 text-green-500" />;
      case 'added':
        return <Plus className="h-4 w-4 text-green-500" />;
      case 'expired':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4" />;
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-isimbi-purple" />
              Domain Monitor
            </CardTitle>
            <CardDescription>Track visited domains and monitor for suspicious activity</CardDescription>
          </div>
          
          <div className="flex gap-2">
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="h-8">
                  <Plus className="h-4 w-4 mr-1" />
                  Add Domain
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add Domain to Monitor</DialogTitle>
                  <DialogDescription>
                    Enter the domain you want to monitor for certificate and DNS changes
                  </DialogDescription>
                </DialogHeader>
                <div className="py-4">
                  <Input 
                    placeholder="example.com" 
                    value={newDomain}
                    onChange={(e) => setNewDomain(e.target.value)}
                  />
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setNewDomain('')}>Cancel</Button>
                  <Button onClick={addDomain} disabled={isAddingDomain}>
                    {isAddingDomain ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Adding...
                      </>
                    ) : (
                      <>Add Domain</>
                    )}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
            
            <Button 
              variant="outline" 
              size="sm" 
              className="h-8"
              onClick={checkDomainCertificates}
              disabled={isChecking}
            >
              {isChecking ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4 mr-1" />
                  Check Now
                </>
              )}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      <div className="border-b border-border">
        <Tabs defaultValue="domains" onValueChange={setActiveTab}>
          <div className="px-6">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="domains">Monitored Domains</TabsTrigger>
              <TabsTrigger value="activity">Domain Activity</TabsTrigger>
            </TabsList>
          </div>
          
          <TabsContent value="domains" className="p-6 pt-4">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-sm font-medium">Domains ({monitoredDomains.length})</h3>
                <div className="flex gap-1">
                  <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                    {monitoredDomains.filter(d => d.status === 'active').length} Active
                  </Badge>
                  <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">
                    {monitoredDomains.filter(d => d.status === 'warning').length} Warning
                  </Badge>
                  <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">
                    {monitoredDomains.filter(d => d.status === 'critical' || d.status === 'expired').length} Critical
                  </Badge>
                </div>
              </div>
              
              <div className="border rounded-md overflow-hidden">
                {monitoredDomains.length > 0 ? (
                  <ScrollArea className="h-[400px]">
                    <div className="divide-y">
                      {monitoredDomains.map((domain) => (
                        <div 
                          key={domain.id} 
                          className={`
                            p-4 hover:bg-muted/50 cursor-pointer
                            ${domain.status === 'critical' || domain.status === 'expired' ? 'bg-red-500/5' : 
                              domain.status === 'warning' ? 'bg-amber-500/5' : ''}
                          `}
                          onClick={() => setSelectedDomain(domain)}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="font-medium">{domain.domain}</div>
                            <div className="flex items-center gap-2">
                              {getStatusBadge(domain.status)}
                              <span className="text-xs text-muted-foreground">
                                Last check: {domain.lastCheck.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          
                          <div className="grid grid-cols-2 gap-4 text-xs">
                            <div>
                              <span className="text-muted-foreground">Certificate expires: </span>
                              <span className={`
                                font-medium
                                ${domain.daysToExpiry < 0 ? 'text-red-500' :
                                  domain.daysToExpiry < 10 ? 'text-red-500' :
                                  domain.daysToExpiry < 30 ? 'text-amber-500' : ''}
                              `}>
                                {domain.daysToExpiry < 0 ? 'Expired' : `${domain.daysToExpiry} days`}
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Issuer: </span>
                              <span>{domain.issuer || 'Unknown'}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">IP Addresses: </span>
                              <span>{domain.ipAddresses.length > 0 ? domain.ipAddresses[0] : 'Unknown'}</span>
                              {domain.ipAddresses.length > 1 && <span> +{domain.ipAddresses.length - 1}</span>}
                            </div>
                            <div>
                              <span className="text-muted-foreground">Registrar: </span>
                              <span>{domain.registrar || 'Unknown'}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="p-8 text-center text-sm text-muted-foreground">
                    No domains are currently being monitored
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="activity" className="p-6 pt-4">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-sm font-medium">Recent Activities ({domainActivities.length})</h3>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" className="h-8 text-xs">Filter</Button>
                  <Button variant="outline" size="sm" className="h-8 text-xs">Export Log</Button>
                </div>
              </div>
              
              <div className="border rounded-md overflow-hidden">
                {domainActivities.length > 0 ? (
                  <ScrollArea className="h-[400px]">
                    <div className="divide-y">
                      {domainActivities.map((activity) => (
                        <div 
                          key={activity.id} 
                          className={`
                            p-4 hover:bg-muted/50
                            ${activity.importance === 'high' ? 'bg-red-500/5' : 
                              activity.importance === 'medium' ? 'bg-amber-500/5' : ''}
                          `}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <div className="font-medium flex items-center gap-1">
                              {getActivityIcon(activity.activityType)}
                              <span>{activity.domain}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              {getImportanceBadge(activity.importance)}
                              <span className="text-xs text-muted-foreground">
                                {activity.timestamp.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          
                          <div className="text-sm mt-1">
                            {activity.details}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="p-8 text-center text-sm text-muted-foreground">
                    No domain activity recorded
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
      
      <CardFooter className="bg-card/50 border-t border-border/50 p-4 flex justify-between">
        <div className="text-xs text-muted-foreground flex items-center">
          <Clock className="h-3.5 w-3.5 mr-1" />
          Last updated: {new Date().toLocaleTimeString()}
        </div>
        <Button variant="outline" size="sm" className="h-8 text-xs flex items-center gap-1">
          <ExternalLink size={14} />
          View Full Report
        </Button>
      </CardFooter>
      
      {/* Domain details dialog */}
      <Dialog open={!!selectedDomain} onOpenChange={(open) => !open && setSelectedDomain(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Domain Details
            </DialogTitle>
            <DialogDescription>
              Detailed information about {selectedDomain?.domain}
            </DialogDescription>
          </DialogHeader>
          
          {selectedDomain && (
            <div className="py-4 space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-medium">{selectedDomain.domain}</h3>
                {getStatusBadge(selectedDomain.status)}
              </div>
              
              <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Certificate Expiry</div>
                  <div className={`
                    font-medium
                    ${selectedDomain.daysToExpiry < 0 ? 'text-red-500' :
                      selectedDomain.daysToExpiry < 10 ? 'text-red-500' :
                      selectedDomain.daysToExpiry < 30 ? 'text-amber-500' : ''}
                  `}>
                    {selectedDomain.expiryDate.toLocaleDateString()} 
                    ({selectedDomain.daysToExpiry < 0 ? 'Expired' : `${selectedDomain.daysToExpiry} days left`})
                  </div>
                </div>
                
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Certificate Issuer</div>
                  <div>{selectedDomain.issuer || 'Unknown'}</div>
                </div>
                
                <div>
                  <div className="text-sm text-muted-foreground mb-1">IP Addresses</div>
                  <div>
                    {selectedDomain.ipAddresses.map((ip, i) => (
                      <div key={i}>{ip}</div>
                    ))}
                  </div>
                </div>
                
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Domain Registrar</div>
                  <div>{selectedDomain.registrar || 'Unknown'}</div>
                </div>
                
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Last Check</div>
                  <div>{selectedDomain.lastCheck.toLocaleString()}</div>
                </div>
                
                <div>
                  <div className="text-sm text-muted-foreground mb-1">DNS Lookups</div>
                  <div>{selectedDomain.lookupCount} lookups recorded</div>
                </div>
              </div>
              
              <div className="border-t pt-4 mt-4">
                <h3 className="font-medium mb-2">Recent Activity</h3>
                <div className="border rounded-md overflow-hidden">
                  <ScrollArea className="h-[150px]">
                    {domainActivities.filter(a => a.domain === selectedDomain.domain).length > 0 ? (
                      <div className="divide-y">
                        {domainActivities
                          .filter(a => a.domain === selectedDomain.domain)
                          .map((activity) => (
                            <div key={activity.id} className="p-3 hover:bg-muted/50">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-1">
                                  {getActivityIcon(activity.activityType)}
                                  <span className="text-sm">{activity.details}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-muted-foreground">
                                    {activity.timestamp.toLocaleTimeString()}
                                  </span>
                                </div>
                              </div>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="p-4 text-center text-sm text-muted-foreground">
                        No recent activity for this domain
                      </div>
                    )}
                  </ScrollArea>
                </div>
              </div>
            </div>
          )}
          
          <DialogFooter>
            <Button variant="outline">Export Details</Button>
            <Button onClick={() => setSelectedDomain(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
};

export default DomainMonitor;
