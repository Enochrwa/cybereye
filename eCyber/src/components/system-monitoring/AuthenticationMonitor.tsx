
import React, { useState, useEffect } from 'react';
import { 
  User, Clock, Search, Shield, AlertTriangle, 
  Filter, RefreshCcw, Lock, Unlock, UserX
} from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

// Types for authentication event
interface AuthEvent {
  id: string;
  timestamp: Date;
  eventType: 'login-success' | 'login-failed' | 'logout' | 'privilege-escalation' | 'password-change';
  username: string;
  sourceIP: string;
  success: boolean;
  details?: string;
  isAnomaly: boolean;
}

const AuthenticationMonitor = () => {
  const { toast } = useToast();
  const [authEvents, setAuthEvents] = useState<AuthEvent[]>([]);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEventType, setSelectedEventType] = useState<string | null>(null);
  
  // Generate sample authentication events
  const generateAuthEvents = (): AuthEvent[] => {
    const eventTypes: ('login-success' | 'login-failed' | 'logout' | 'privilege-escalation' | 'password-change')[] = [
      'login-success', 'login-failed', 'logout', 'privilege-escalation', 'password-change'
    ];
    const usernames = [
      'admin', 'john.doe', 'jane.smith', 'root', 'sysadmin', 'developer', 'guest', 'support'
    ];
    const sourceIPs = [
      '192.168.1.100', '192.168.1.101', '192.168.1.102',
      '10.0.0.15', '10.0.0.23',
      '172.16.254.1',
      '54.239.28.85', // external IPs
      '157.240.22.35'
    ];
    
    const eventsCount = Math.floor(Math.random() * 10) + 15; // 15-24 events
    const events: AuthEvent[] = [];
    const now = new Date();
    
    for (let i = 0; i < eventsCount; i++) {
      const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
      const username = usernames[Math.floor(Math.random() * usernames.length)];
      const sourceIP = sourceIPs[Math.floor(Math.random() * sourceIPs.length)];
      const timestamp = new Date(now.getTime() - Math.random() * 86400000); // Random time within last 24 hours
      const success = eventType !== 'login-failed' ? Math.random() > 0.2 : false;
      
      // Determine if this is an anomalous event
      let isAnomaly = false;
      let details = '';
      
      if (eventType === 'login-failed' && Math.random() > 0.7) {
        isAnomaly = true;
        details = 'Multiple failed login attempts detected';
      } else if (eventType === 'privilege-escalation' && Math.random() > 0.8) {
        isAnomaly = true;
        details = 'Unusual privilege escalation detected';
      } else if (username === 'root' && sourceIP.startsWith('54.') || sourceIP.startsWith('157.')) {
        isAnomaly = true;
        details = 'Root login from external IP address';
      } else if (timestamp.getHours() >= 1 && timestamp.getHours() <= 4 && Math.random() > 0.7) {
        isAnomaly = true;
        details = 'Unusual login time (after hours)';
      }
      
      events.push({
        id: `auth-${Date.now()}-${i}`,
        timestamp,
        eventType,
        username,
        sourceIP,
        success,
        details,
        isAnomaly
      });
    }
    
    // Sort by timestamp (newest first)
    return events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  };
  
  // Initialize and refresh events
  useEffect(() => {
    const events = generateAuthEvents();
    setAuthEvents(events);
    
    // Add random authentication events periodically
    const interval = setInterval(() => {
      const eventTypes: ('login-success' | 'login-failed' | 'logout')[] = [
        'login-success', 'login-failed', 'logout'
      ];
      const usernames = ['admin', 'john.doe', 'jane.smith', 'root', 'sysadmin'];
      const sourceIPs = ['192.168.1.100', '192.168.1.101', '10.0.0.15', '54.239.28.85'];
      
      const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
      const username = usernames[Math.floor(Math.random() * usernames.length)];
      const sourceIP = sourceIPs[Math.floor(Math.random() * sourceIPs.length)];
      const success = eventType !== 'login-failed' ? true : false;
      
      // Determine if this is an anomaly
      let isAnomaly = false;
      let details = '';
      
      if (Math.random() > 0.9) {
        isAnomaly = true;
        
        if (eventType === 'login-failed') {
          details = 'Multiple failed login attempts detected';
        } else if (username === 'root' && !sourceIP.startsWith('192.168.')) {
          details = 'Root login from external IP address';
        } else {
          details = 'Unusual login pattern detected';
        }
        
        toast({
          title: "Authentication Anomaly Detected",
          description: `${details} for user ${username}`,
          variant: "destructive"
        });
      }
      
      const newEvent: AuthEvent = {
        id: `auth-${Date.now()}`,
        timestamp: new Date(),
        eventType,
        username,
        sourceIP,
        success,
        details,
        isAnomaly
      };
      
      setAuthEvents(prev => [newEvent, ...prev].slice(0, 100));
    }, 12000); // Add new event every 12 seconds
    
    return () => clearInterval(interval);
  }, [toast]);
  
  // Filter events based on search term, event type, and anomaly flag
  const filteredEvents = authEvents.filter(event => {
    const matchesSearch = !searchTerm || 
      event.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.sourceIP.includes(searchTerm) ||
      (event.details && event.details.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesEventType = !selectedEventType || event.eventType === selectedEventType;
    
    return matchesSearch && matchesEventType && (!showAnomaliesOnly || event.isAnomaly);
  });
  
  // Get event icon based on event type
  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'login-success':
        return <Unlock className="h-4 w-4 text-green-500" />;
      case 'login-failed':
        return <Lock className="h-4 w-4 text-red-500" />;
      case 'logout':
        return <UserX className="h-4 w-4 text-blue-500" />;
      case 'privilege-escalation':
        return <Shield className="h-4 w-4 text-amber-500" />;
      case 'password-change':
        return <Lock className="h-4 w-4 text-purple-500" />;
      default:
        return <User className="h-4 w-4" />;
    }
  };
  
  // Format event type for display
  const formatEventType = (eventType: string): string => {
    return eventType
      .split('-')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Authentication Events</h3>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search username or IP..."
              className="pl-8 h-9 w-[220px] rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Button 
            size="sm" 
            variant={showAnomaliesOnly ? "default" : "outline"} 
            className="h-9 gap-1"
            onClick={() => setShowAnomaliesOnly(!showAnomaliesOnly)}
          >
            <AlertTriangle className="h-4 w-4" />
            {showAnomaliesOnly ? "Show All" : "Anomalies Only"}
          </Button>
          <Button 
            size="sm" 
            className="h-9 gap-1"
            onClick={() => setAuthEvents(generateAuthEvents())}
          >
            <RefreshCcw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>
      
      {/* Event Type Filter */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2">
        <Button 
          variant={selectedEventType === null ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType(null)}
        >
          All Events
        </Button>
        <Button 
          variant={selectedEventType === 'login-success' ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType('login-success')}
        >
          <Unlock className="mr-1 h-4 w-4" /> 
          Login Success
        </Button>
        <Button 
          variant={selectedEventType === 'login-failed' ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType('login-failed')}
        >
          <Lock className="mr-1 h-4 w-4" /> 
          Login Failed
        </Button>
        <Button 
          variant={selectedEventType === 'logout' ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType('logout')}
        >
          <UserX className="mr-1 h-4 w-4" /> 
          Logout
        </Button>
        <Button 
          variant={selectedEventType === 'privilege-escalation' ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType('privilege-escalation')}
        >
          <Shield className="mr-1 h-4 w-4" /> 
          Privilege Escalation
        </Button>
        <Button 
          variant={selectedEventType === 'password-change' ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedEventType('password-change')}
        >
          <Lock className="mr-1 h-4 w-4" /> 
          Password Change
        </Button>
      </div>
      
      {/* Auth Events Table */}
      <div className="border rounded-lg overflow-hidden">
        <div className="grid grid-cols-7 gap-2 py-2 px-3 bg-muted text-xs font-medium">
          <div className="col-span-1">Time</div>
          <div className="col-span-1">Event Type</div>
          <div className="col-span-1">Username</div>
          <div className="col-span-1">Source IP</div>
          <div className="col-span-1">Status</div>
          <div className="col-span-2">Details</div>
        </div>
        
        <ScrollArea className="h-[500px]">
          {filteredEvents.length > 0 ? (
            <div className="divide-y">
              {filteredEvents.map((event) => (
                <div 
                  key={event.id}
                  className={`grid grid-cols-7 gap-2 py-2 px-3 text-xs ${
                    event.isAnomaly ? 'bg-red-500/5' : ''
                  } hover:bg-muted/50`}
                >
                  <div className="col-span-1">
                    {event.timestamp.toLocaleTimeString()}
                    <div className="text-[10px] text-muted-foreground">
                      {event.timestamp.toLocaleDateString()}
                    </div>
                  </div>
                  <div className="col-span-1 flex items-center gap-1">
                    {getEventIcon(event.eventType)}
                    <span>{formatEventType(event.eventType)}</span>
                  </div>
                  <div className="col-span-1 font-medium">
                    {event.username}
                  </div>
                  <div className="col-span-1 font-mono">
                    {event.sourceIP}
                  </div>
                  <div className="col-span-1">
                    {event.success ? (
                      <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                        Success
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">
                        Failed
                      </Badge>
                    )}
                  </div>
                  <div className="col-span-2 flex items-center">
                    {event.isAnomaly && <AlertTriangle className="h-3 w-3 text-red-500 mr-1" />}
                    <span className={event.isAnomaly ? 'text-red-500' : 'text-muted-foreground'}>
                      {event.details || (event.success ? 'Normal authentication event' : 'Authentication failed')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No authentication events found matching your criteria
            </div>
          )}
        </ScrollArea>
      </div>
      
      {/* Authentication Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Total Events</div>
          <div className="text-2xl font-bold">{authEvents.length}</div>
          <div className="text-xs text-muted-foreground mt-1">In last 24 hours</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Successful Logins</div>
          <div className="text-2xl font-bold text-green-500">
            {authEvents.filter(e => e.eventType === 'login-success' && e.success).length}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Authenticated sessions</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Failed Attempts</div>
          <div className="text-2xl font-bold text-red-500">
            {authEvents.filter(e => e.eventType === 'login-failed' || !e.success).length}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Failed authentication attempts</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Anomalies</div>
          <div className="text-2xl font-bold text-amber-500">
            {authEvents.filter(e => e.isAnomaly).length}
          </div>
          <div className="text-xs text-muted-foreground mt-1">Suspicious authentication events</div>
        </div>
      </div>
    </div>
  );
};

export default AuthenticationMonitor;
