
import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Shield, BarChart2, PieChart, Activity, Globe } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

// This would normally import a charting library like Recharts
// We'll simulate the visualization with tailwind styling

// Define EmergingThreat type for props, compatible with data from Threats.tsx
// This could be imported from Threats.tsx if exported, or from a shared types file.
export interface EmergingThreat { // Renamed from EmergingThreatDisplay for local context if preferred
  keyId: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "warning" | "unknown";
  type: string; 
  details: string;
  affectedSystems?: string[];
  timestamp?: Date;
  detectionCount?: number;
  backendType: string;
  backendSource: string;
  id?: string;
  summary?: string;
  indicator?: string;
  indicator_type?: string;
  source: string; 
  published?: string;
  last_seen?: string;
}

interface TimelineDataPoint {
  date: string; // Example: "2023-11-01"
  count: number;
}

interface TypeDataPoint {
  name: string; // Example: "CVE"
  value: number;
}


interface ThreatVisualizationProps {
  threats: EmergingThreat[]; // Using the locally defined EmergingThreat type
  timelineData: TimelineDataPoint[]; // Mock data structure
  typesData: TypeDataPoint[];     // Mock data structure
}

const ThreatVisualization: React.FC<ThreatVisualizationProps> = ({ threats, timelineData, typesData }) => {
  const [activeTab, setActiveTab] = useState('global');
  
  // For now, the component will not use the passed props to render dynamic charts.
  // Static placeholders will remain.
  // console.log("ThreatVisualization received threats:", threats);
  // console.log("ThreatVisualization received timelineData:", timelineData);
  // console.log("ThreatVisualization received typesData:", typesData);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base flex items-center">
          <Shield className="mr-2" size={16} />
          Threat Intelligence Analysis
        </CardTitle>
        <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-[400px]">
          <TabsList>
            <TabsTrigger value="global">Global View</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="types">Threat Types</TabsTrigger>
            <TabsTrigger value="sources">Sources</TabsTrigger>
          </TabsList>
        </Tabs>
      </CardHeader>
      <CardContent>
        <div className="h-80 border border-border rounded-lg bg-background/50 overflow-hidden">
          <Tabs value={activeTab}>
            <TabsContent value="global" className="h-full">
              <div className="h-full flex items-center justify-center">
                {/* Simulated world map with threat hotspots */}
                <div className="relative w-full h-full p-4">
                  <Globe className="w-full h-full text-muted-foreground opacity-10" />
                  
                  {/* Simulated hotspots */}
                  <div className="absolute top-[30%] left-[25%] w-4 h-4 bg-red-500 rounded-full animate-pulse" />
                  <div className="absolute top-[40%] left-[47%] w-5 h-5 bg-amber-500 rounded-full animate-pulse" />
                  <div className="absolute top-[35%] left-[80%] w-6 h-6 bg-red-500 rounded-full animate-pulse" />
                  <div className="absolute top-[70%] left-[30%] w-3 h-3 bg-blue-500 rounded-full animate-pulse" />
                  
                  <div className="absolute bottom-4 right-4 bg-card/80 backdrop-blur rounded-md p-2">
                    <div className="text-xs font-medium">Threat Hotspots</div>
                    <div className="flex items-center mt-1">
                      <div className="w-3 h-3 rounded-full bg-red-500 mr-1" />
                      <span className="text-xs">Critical (2)</span>
                    </div>
                    <div className="flex items-center">
                      <div className="w-3 h-3 rounded-full bg-amber-500 mr-1" />
                      <span className="text-xs">Warning (1)</span>
                    </div>
                    <div className="flex items-center">
                      <div className="w-3 h-3 rounded-full bg-blue-500 mr-1" />
                      <span className="text-xs">Info (1)</span>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="timeline" className="h-full">
              <div className="h-full flex flex-col p-4">
                <div className="flex justify-between items-center mb-2">
                  <div className="text-xs font-medium">Event Frequency</div>
                  <div className="text-xs text-muted-foreground">Last 7 days</div>
                </div>
                <div className="flex-1 flex items-end space-x-2">
                  {/* Simulated bar chart */}
                  {[35, 28, 45, 65, 40, 55, 70].map((height, i) => (
                    <div key={i} className="flex-1 flex flex-col items-center">
                      <div 
                        className="w-full bg-blue-500/80 rounded-t"
                        style={{ height: `${height}%` }}
                      />
                      <div className="text-xs mt-1">{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][i]}</div>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="types" className="h-full">
              <div className="h-full flex items-center justify-center p-4">
                {/* Simulated pie chart */}
                <div className="relative w-48 h-48">
                  <div className="absolute inset-0 bg-blue-500 rounded-full overflow-hidden">
                    <div className="absolute w-1/2 h-full right-0 bg-red-500" />
                    <div className="absolute w-1/2 h-1/2 bottom-0 left-0 bg-amber-500" />
                    <div className="absolute w-1/4 h-1/4 top-0 left-0 bg-green-500" />
                    <div className="absolute w-6 h-6 rounded-full bg-card top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
                  </div>
                  <div className="absolute top-full mt-4 w-full">
                    <div className="grid grid-cols-2 gap-2">
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full bg-blue-500 mr-1" />
                        <span className="text-xs">Malware (35%)</span>
                      </div>
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full bg-red-500 mr-1" />
                        <span className="text-xs">Ransomware (30%)</span>
                      </div>
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full bg-amber-500 mr-1" />
                        <span className="text-xs">Phishing (25%)</span>
                      </div>
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full bg-green-500 mr-1" />
                        <span className="text-xs">Other (10%)</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="sources" className="h-full">
              <div className="h-full p-4">
                <div className="text-xs font-medium mb-2">Threat Intelligence Sources</div>
                <div className="space-y-3">
                  {[
                    { name: 'MITRE ATT&CK', percentage: 35 },
                    { name: 'OSINT Feed', percentage: 28 },
                    { name: 'Threat Intel', percentage: 22 },
                    { name: 'CVE Database', percentage: 15 }
                  ].map((source, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sm">{source.name}</span>
                        <span className="text-sm">{source.percentage}%</span>
                      </div>
                      <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-blue-500 rounded-full" 
                          style={{ width: `${source.percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatVisualization;
