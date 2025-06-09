import React, { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowRight, AlertOctagon, Shield, Loader2 } from 'lucide-react';
// Header import removed as it's not used in the provided code snippet for Threats page directly
// import Header from '../components/layout/Header'; 
import ThreatVisualization, { EmergingThreat as TVEmergingThreat } from '../components/threats/ThreatVisualization'; // Assuming EmergingThreat type is exported by ThreatVisualization for its props
import ThreatFeedsInteractive from '../components/threats/ThreatFeedsInteractive';


// Backend EmergingThreat structure (for reference during mapping)
interface BackendEmergingThreat {
  type: string;
  id?: string; // CVE ID or similar unique identifier from backend
  summary?: string; // For CVEs
  indicator?: string; // For OSINT
  indicator_type?: string; // For OSINT
  threat_type?: string; // For OSINT (e.g. malware_printable)
  source: string;
  published?: string; // For CVEs (ISO date string)
  last_seen?: string; // For OSINT (ISO date string)
}

// Frontend display structure for Emerging Threats
// This will be passed to ThreatVisualization as well
export interface EmergingThreatDisplay extends TVEmergingThreat { // Ensure it's compatible with ThreatVisualization's expected prop
  keyId: string; // Unique key for React rendering (can be derived from backend id or indicator)
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "warning" | "unknown"; // Adjusted to match existing styling logic if possible
  details: string;
  affectedSystems?: string[]; // This is not directly in backend data, might be omitted or derived
  timestamp?: Date; // Can use 'published' or 'last_seen'
  detectionCount?: number; // Not in backend data, might be omitted
  // Retain fields from BackendEmergingThreat that are useful directly
  backendType: string; // Original 'type' from backend (e.g. "CVE", "OSINT Indicator")
  backendSource: string; // Original 'source' from backend
}


const Threats = () => {
  const [emergingThreatsData, setEmergingThreatsData] = useState<EmergingThreatDisplay[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchEmergingThreats = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/threat-intelligence/emerging-threats');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: BackendEmergingThreat[] = await response.json();
        
        const processedData: EmergingThreatDisplay[] = data.map((threat, index) => {
          let severity: EmergingThreatDisplay["severity"] = "unknown";
          if (threat.type === 'CVE') {
            // Example: derive severity for CVEs, perhaps from a CVSS score if available, or default
            severity = "high"; // Placeholder
          } else if (threat.type === 'OSINT Indicator') {
            // Example: derive severity for OSINT, perhaps based on threat_type or confidence if available
            if (threat.threat_type?.toLowerCase().includes("malware")) severity = "medium";
            else if (threat.indicator_type === "phishing") severity = "medium";
            else severity = "low";
          }

          return {
            keyId: threat.id || threat.indicator || `et-${index}`,
            name: threat.id || threat.indicator || 'N/A', // Use CVE ID or indicator value as name
            severity: severity,
            type: threat.type, // This is the backend type, used for icon, etc.
            details: threat.summary || threat.threat_type || 'No specific details provided.',
            affectedSystems: [], // Not available from this backend endpoint
            timestamp: threat.published ? new Date(threat.published) : (threat.last_seen ? new Date(threat.last_seen) : undefined),
            detectionCount: undefined, // Not available
            backendType: threat.type,
            backendSource: threat.source,
            // Ensure all fields expected by TVEmergingThreat are present
            // If TVEmergingThreat expects 'id', 'summary', etc., map them here
            id: threat.id,
            summary: threat.summary,
            indicator: threat.indicator,
            indicator_type: threat.indicator_type,
            source: threat.source,
            published: threat.published,
            last_seen: threat.last_seen,
          };
        });
        setEmergingThreatsData(processedData);
      } catch (e) {
        if (e instanceof Error) {
          setError(e.message);
        } else {
          setError('An unknown error occurred');
        }
        console.error("Failed to fetch emerging threats:", e);
      } finally {
        setIsLoading(false);
      }
    };

    fetchEmergingThreats();
  }, []);

  // Removed hardcoded threatFeeds, assuming ThreatFeedsInteractive handles its own data

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Threat Intelligence</h1>
              <p className="text-muted-foreground">Track and respond to emerging security threats</p>
            </div>
            
            <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
          
          {/* Emerging threats section */}
          <Card className="mb-6 border-red-500/20 shadow-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg font-medium flex items-center">
                <AlertOctagon className="mr-2 text-red-400" size={18} />
                Emerging Threats
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  <p className="ml-2">Loading emerging threats...</p>
                </div>
              )}
              {error && (
                <div className="text-red-500 py-4 text-center">
                  Error fetching threats: {error}
                </div>
              )}
              {!isLoading && !error && emergingThreatsData.length === 0 && (
                <div className="text-muted-foreground py-4 text-center">
                  No emerging threats found.
                </div>
              )}
              {!isLoading && !error && emergingThreatsData.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {emergingThreatsData.map((threat) => (
                    <div 
                      key={threat.keyId}
                      className={cn(
                        "glass-card p-4 border rounded-lg",
                        threat.severity === 'critical' || threat.severity === 'high' ? "border-red-500/20" : "border-amber-500/20"
                      )}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <h3 className="font-medium text-sm">{threat.name}</h3>
                        <Badge 
                          variant="outline"
                          className={cn(
                            "text-xs",
                            threat.severity === 'critical' || threat.severity === 'high' ? "border-red-500 text-red-400" : "border-amber-500 text-amber-400"
                          )}
                        >
                          {threat.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">{threat.backendType} (Source: {threat.backendSource})</p>
                      <p className="text-xs mb-3 h-10 overflow-y-auto">{threat.details}</p>
                      {/* Affected Systems and Detection Count are not directly available from backend */}
                      {/* Timestamp can be displayed */}
                      {threat.timestamp && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {threat.backendType === 'CVE' ? 'Published: ' : 'Last Seen: '} 
                          {new Date(threat.timestamp).toLocaleDateString()}
                        </p>
                      )}
                      <div className="flex items-center justify-between mt-3 pt-2 border-t border-border/50">
                        <span className="text-xs text-muted-foreground">
                          {/* Detection count placeholder or remove */}
                        </span>
                        <Button variant="ghost" size="sm" className="h-6 text-xs">
                          Investigate <ArrowRight className="ml-1" size={12} />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
          
          {/* Threat analysis and feeds section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-2">
              {/* Pass the fetched and processed emergingThreatsData to ThreatVisualization */}
              <ThreatVisualization threats={emergingThreatsData} />
            </div>
            
            <div>
              <ThreatFeedsInteractive />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Threats;
