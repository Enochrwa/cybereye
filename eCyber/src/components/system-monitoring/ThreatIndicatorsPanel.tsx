
import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, RefreshCcw, Activity, Cpu, 
  HardDrive, Network, Wifi, Globe, ArrowUpRight, Search 
} from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";

// Define threat indicator type
interface ThreatIndicator {
  id: string;
  name: string;
  category: 'process' | 'file' | 'network' | 'memory' | 'behavior';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: Date;
  details: string;
  isActive: boolean;
}

const ThreatIndicatorsPanel = () => {
  const { toast } = useToast();
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [riskScore, setRiskScore] = useState(15);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Generate sample threat indicators
  const generateThreatIndicators = () => {
    const threatCategories: ('process' | 'file' | 'network' | 'memory' | 'behavior')[] = [
      'process', 'file', 'network', 'memory', 'behavior'
    ];
    
    const threatNames = [
      'Suspicious process activity',
      'Unusual outbound network traffic',
      'Modified system files',
      'Multiple failed login attempts',
      'Memory corruption attempt',
      'Potential data exfiltration',
      'Configuration file changes',
      'Unusual CPU usage pattern',
      'Unexpected privileged access',
      'Port scanning activity'
    ];
    
    const threatDescriptions = [
      'Process attempting to access protected memory regions',
      'High volume of outbound traffic to unusual IP ranges',
      'Critical system files modified outside of update process',
      'Repeated failed login attempts from multiple IPs',
      'Memory regions showing signs of buffer overflow attempts',
      'Large data transfers to external endpoints',
      'Critical configuration files modified by unauthorized process',
      'Sustained high CPU usage by background process',
      'Unexpected privilege escalation detected',
      'Connection attempts to multiple ports in sequence'
    ];
    
    const indicatorsCount = Math.floor(Math.random() * 5) + 3; // 3-7 indicators
    const indicators: ThreatIndicator[] = [];
    const now = new Date();
    
    for (let i = 0; i < indicatorsCount; i++) {
      const category = threatCategories[Math.floor(Math.random() * threatCategories.length)];
      const nameIndex = Math.floor(Math.random() * threatNames.length);
      const name = threatNames[nameIndex];
      const description = threatDescriptions[nameIndex];
      
      // Randomly assign severity with weighted distribution
      const rand = Math.random();
      let severity: 'low' | 'medium' | 'high' | 'critical';
      
      if (rand < 0.4) severity = 'low';
      else if (rand < 0.7) severity = 'medium';
      else if (rand < 0.9) severity = 'high';
      else severity = 'critical';
      
      indicators.push({
        id: `threat-${Date.now()}-${i}`,
        name,
        category,
        severity,
        description,
        timestamp: new Date(now.getTime() - Math.floor(Math.random() * 3600000)), // Within last hour
        details: `Detected on ${category === 'process' ? 'process ID' : category === 'network' ? 'port' : 'path'} ${Math.floor(Math.random() * 1000)}`,
        isActive: Math.random() > 0.3 // 70% are active
      });
    }
    
    return indicators.sort((a, b) => {
      // Sort by severity (critical first) and then by timestamp (newest first)
      const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      
      if (severityDiff !== 0) return severityDiff;
      return b.timestamp.getTime() - a.timestamp.getTime();
    });
  };
  
  // Calculate risk score based on threat indicators
  const calculateRiskScore = (threats: ThreatIndicator[]): number => {
    if (threats.length === 0) return 0;
    
    const severityScores = {
      'critical': 25,
      'high': 15,
      'medium': 8,
      'low': 3
    };
    
    // Calculate base score from active threats
    const activeThreats = threats.filter(t => t.isActive);
    if (activeThreats.length === 0) return Math.max(5, Math.floor(threats.length * 1.5));
    
    const baseScore = activeThreats.reduce((score, threat) => {
      return score + severityScores[threat.severity];
    }, 0);
    
    // Add some randomness to simulate dynamic analysis
    const randomFactor = Math.floor(Math.random() * 10) - 5; // -5 to +4
    
    return Math.min(100, Math.max(0, baseScore + randomFactor));
  };
  
  // Get color based on risk score
  const getRiskScoreColor = (score: number): string => {
    if (score < 20) return 'text-green-500';
    if (score < 40) return 'text-amber-500';
    if (score < 70) return 'text-orange-500';
    return 'text-red-500';
  };
  
  // Get progress color based on risk score
  const getRiskScoreProgressColor = (score: number): string => {
    if (score < 20) return 'bg-green-500';
    if (score < 40) return 'bg-amber-500';
    if (score < 70) return 'bg-orange-500';
    return 'bg-red-500';
  };
  
  // Get severity badge
  const getSeverityBadge = (severity: 'low' | 'medium' | 'high' | 'critical') => {
    switch (severity) {
      case 'critical':
        return <Badge variant="destructive">Critical</Badge>;
      case 'high':
        return <Badge className="bg-orange-500 hover:bg-orange-600">High</Badge>;
      case 'medium':
        return <Badge className="bg-amber-500 hover:bg-amber-600">Medium</Badge>;
      case 'low':
        return <Badge className="bg-green-500 hover:bg-green-600">Low</Badge>;
    }
  };
  
  // Get category icon
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'process':
        return <Cpu className="h-4 w-4 text-blue-500" />;
      case 'file':
        return <HardDrive className="h-4 w-4 text-green-500" />;
      case 'network':
        return <Globe className="h-4 w-4 text-amber-500" />;
      case 'memory':
        return <Network className="h-4 w-4 text-purple-500" />;
      case 'behavior':
        return <Activity className="h-4 w-4 text-red-500" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };
  
  // Format category for display
  const formatCategory = (category: string): string => {
    return category.charAt(0).toUpperCase() + category.slice(1);
  };
  
  // Initialize and refresh indicators
  useEffect(() => {
    const threats = generateThreatIndicators();
    setIndicators(threats);
    setRiskScore(calculateRiskScore(threats));
    
    // Simulate new threat indicators periodically
    const interval = setInterval(() => {
      if (Math.random() > 0.7) { // 30% chance to add new threat
        const newThreatCategories: ('process' | 'file' | 'network' | 'memory' | 'behavior')[] = [
          'process', 'network', 'behavior'
        ];
        const newThreatCategory = newThreatCategories[Math.floor(Math.random() * newThreatCategories.length)];
        const newThreatName = newThreatCategory === 'process' ? 'Suspicious process activity' : 
                             newThreatCategory === 'network' ? 'Unusual outbound network traffic' : 
                             'Unusual user behavior pattern';
        const severity = Math.random() > 0.8 ? 'high' : 'medium';
        
        const newThreat: ThreatIndicator = {
          id: `threat-${Date.now()}`,
          name: newThreatName,
          category: newThreatCategory,
          severity: severity,
          description: `Newly detected ${newThreatCategory} based threat indicator`,
          timestamp: new Date(),
          details: `Detected on ${newThreatCategory === 'process' ? 'process ID' : newThreatCategory === 'network' ? 'port' : 'session'} ${Math.floor(Math.random() * 1000)}`,
          isActive: true
        };
        
        setIndicators(prev => {
          const updated = [newThreat, ...prev];
          // Update risk score when adding new threat
          const newRiskScore = calculateRiskScore(updated);
          setRiskScore(newRiskScore);
          return updated;
        });
        
        if (severity === 'high') {
          toast({
            title: "New High Severity Threat Detected",
            description: newThreatName,
            variant: "destructive"
          });
        }
      }
    }, 20000); // Check every 20 seconds
    
    return () => clearInterval(interval);
  }, [toast]);
  
  // Handle refresh button
  const handleRefresh = () => {
    setIsRefreshing(true);
    
    // Simulate refresh delay
    setTimeout(() => {
      const threats = generateThreatIndicators();
      setIndicators(threats);
      setRiskScore(calculateRiskScore(threats));
      setIsRefreshing(false);
      
      toast({
        title: "Threat Analysis Updated",
        description: "Latest threat indicators have been refreshed"
      });
    }, 1500);
  };
  
  // Clear all threats (for demo purposes)
  const clearAllThreats = () => {
    setIndicators([]);
    setRiskScore(0);
    
    toast({
      title: "All Threats Cleared",
      description: "Threat indicators have been reset"
    });
  };
  
  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Threat Indicators</h3>
        <div className="flex items-center gap-2">
          <Button 
            size="sm" 
            variant="outline" 
            className="h-9 gap-1"
            onClick={clearAllThreats}
          >
            Clear All
          </Button>
          <Button 
            size="sm" 
            className="h-9 gap-1"
            onClick={handleRefresh}
            disabled={isRefreshing}
          >
            <RefreshCcw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'Updating...' : 'Refresh'}
          </Button>
        </div>
      </div>
      
      {/* Risk Score Meter */}
      <div className="border rounded-lg p-4">
        <div className="flex justify-between items-start mb-3">
          <div>
            <h4 className="text-sm font-medium">Current Risk Score</h4>
            <div className={`text-3xl font-bold ${getRiskScoreColor(riskScore)}`}>
              {riskScore}
            </div>
            <div className="text-xs text-muted-foreground">
              {riskScore < 20 ? 'Low Risk' : 
               riskScore < 40 ? 'Medium Risk' : 
               riskScore < 70 ? 'High Risk' : 
               'Critical Risk'}
            </div>
          </div>
          
          <div className="text-right">
            <h4 className="text-sm font-medium">Active Threats</h4>
            <div className="text-3xl font-bold">
              {indicators.filter(i => i.isActive).length}
            </div>
            <div className="text-xs text-muted-foreground">
              {indicators.filter(i => i.severity === 'critical' && i.isActive).length > 0 ? 
                'Critical response needed' : 
                indicators.filter(i => i.severity === 'high' && i.isActive).length > 0 ?
                'Immediate action recommended' : 
                'Monitor system status'}
            </div>
          </div>
        </div>
        
        <div className="w-full bg-muted h-4 rounded-full overflow-hidden">
          <div 
            className={`h-full ${getRiskScoreProgressColor(riskScore)} transition-all duration-1000`}
            style={{ width: `${riskScore}%` }}
          ></div>
        </div>
        
        <div className="flex justify-between mt-1 text-xs text-muted-foreground">
          <div>Low (0)</div>
          <div>Medium (40)</div>
          <div>High (70)</div>
          <div>Critical (100)</div>
        </div>
      </div>
      
      {/* Threats by Category */}
      <div className="grid grid-cols-5 gap-4">
        <div className="border rounded-md p-3">
          <div className="flex items-center gap-2 mb-2">
            <Cpu className="h-4 w-4 text-blue-500" />
            <div className="text-sm font-medium">Process Threats</div>
          </div>
          <div className="text-2xl font-bold">
            {indicators.filter(i => i.category === 'process' && i.isActive).length}
          </div>
          <div className="text-xs text-muted-foreground">Active indicators</div>
        </div>
        
        <div className="border rounded-md p-3">
          <div className="flex items-center gap-2 mb-2">
            <HardDrive className="h-4 w-4 text-green-500" />
            <div className="text-sm font-medium">File Threats</div>
          </div>
          <div className="text-2xl font-bold">
            {indicators.filter(i => i.category === 'file' && i.isActive).length}
          </div>
          <div className="text-xs text-muted-foreground">Active indicators</div>
        </div>
        
        <div className="border rounded-md p-3">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="h-4 w-4 text-amber-500" />
            <div className="text-sm font-medium">Network Threats</div>
          </div>
          <div className="text-2xl font-bold">
            {indicators.filter(i => i.category === 'network' && i.isActive).length}
          </div>
          <div className="text-xs text-muted-foreground">Active indicators</div>
        </div>
        
        <div className="border rounded-md p-3">
          <div className="flex items-center gap-2 mb-2">
            <Network className="h-4 w-4 text-purple-500" />
            <div className="text-sm font-medium">Memory Threats</div>
          </div>
          <div className="text-2xl font-bold">
            {indicators.filter(i => i.category === 'memory' && i.isActive).length}
          </div>
          <div className="text-xs text-muted-foreground">Active indicators</div>
        </div>
        
        <div className="border rounded-md p-3">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-4 w-4 text-red-500" />
            <div className="text-sm font-medium">Behavior Threats</div>
          </div>
          <div className="text-2xl font-bold">
            {indicators.filter(i => i.category === 'behavior' && i.isActive).length}
          </div>
          <div className="text-xs text-muted-foreground">Active indicators</div>
        </div>
      </div>
      
      {/* Threat Indicators List */}
      <div className="border rounded-lg overflow-hidden">
        <div className="flex justify-between items-center p-4 border-b">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            <h4 className="text-sm font-medium">Threat Indicators</h4>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                type="search"
                placeholder="Search threats..."
                className="pl-8 h-9 w-[220px] rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
          </div>
        </div>
        
        <ScrollArea className="h-[400px]">
          {indicators.length > 0 ? (
            <div className="divide-y">
              {indicators.map((indicator) => (
                <div 
                  key={indicator.id}
                  className={`p-4 hover:bg-muted/50 ${
                    indicator.severity === 'critical' ? 'bg-red-500/5' :
                    indicator.severity === 'high' ? 'bg-orange-500/5' :
                    ''
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-2">
                      {getCategoryIcon(indicator.category)}
                      <div className="font-medium">{indicator.name}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(indicator.severity)}
                      <Badge variant={indicator.isActive ? "default" : "outline"}>
                        {indicator.isActive ? 'Active' : 'Resolved'}
                      </Badge>
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground mt-1">
                    {indicator.description}
                  </div>
                  <div className="flex justify-between items-center mt-2">
                    <div className="text-xs text-muted-foreground flex items-center gap-1">
                      <span className="font-medium">{formatCategory(indicator.category)}</span> • 
                      <span>{indicator.details}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {indicator.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No threat indicators detected
            </div>
          )}
        </ScrollArea>
      </div>
      
      {/* MITRE ATT&CK Framework Mapping */}
      <div className="border rounded-lg p-4">
        <h4 className="text-sm font-medium mb-3">MITRE ATT&CK Framework Mapping</h4>
        <div className="bg-muted h-[200px] rounded-md flex items-center justify-center">
          <span className="text-muted-foreground">MITRE ATT&CK framework mapping visualization would appear here</span>
        </div>
      </div>
    </div>
  );
};

export default ThreatIndicatorsPanel;
