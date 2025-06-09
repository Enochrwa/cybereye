import React, { useState, useEffect, useMemo } from 'react';
import { Socket } from 'socket.io-client';
import { useTheme } from '@/components/theme/ThemeProvider';
import { useTelemetrySocket } from '@/components/live-system/lib/socket';

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrolArea } from "@/components/ui/scroll-area";
import { AlertCircle, TrendingUp, Target, BarChart, Copy, Send, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';

import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';

// AlertData Interface (Adjust based on actual final structure from sniffer.py)
interface AlertData {
  id: string;
  timestamp: string;
  severity: string; // e.g., "Medium", "High"
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  description: string;
  threat_type: string; // Should be "Anomaly"
  rule_id?: string;
  anomaly_score?: number; // Machine learning score
  threshold?: number;     // Threshold used for this anomaly score
  is_anomaly?: number;    // 1 if anomaly, 0 otherwise (or boolean)
  metadata?: {
    model_name?: string;
    features_contributing?: Record<string, any>; // All features model considered
    // Potentially other fields like original_packet_info, flow_id etc.
  };
}

const MAX_ANOMALY_HISTORY = 20;

const AnomalyIsolationCard: React.FC = () => {
  const { theme } = useTheme();
  const { getSocket } = useTelemetrySocket();
  const socket: Socket | null = getSocket();

  const [latestAnomaly, setLatestAnomaly] = useState<AlertData | null>(null);
  const [anomalyHistory, setAnomalyHistory] = useState<AlertData[]>([]);

  useEffect(() => {
    if (socket) {
      const handleAnomalyAlert = (data: AlertData) => {
        setLatestAnomaly(data);
        setAnomalyHistory(prevHistory => {
          const newHistory = [data, ...prevHistory];
          return newHistory.slice(0, MAX_ANOMALY_HISTORY);
        });
      };

      socket.on('ANOMALY_ALERT', handleAnomalyAlert);
      // console.log("AnomalyIsolationCard: Subscribed to ANOMALY_ALERT");

      return () => {
        socket.off('ANOMALY_ALERT', handleAnomalyAlert);
        // console.log("AnomalyIsolationCard: Unsubscribed from ANOMALY_ALERT");
      };
    }
  }, [socket]);

  const getVerdict = (score?: number, threshold?: number): { text: string; color: string; icon: React.ReactNode } => {
    if (score === undefined || threshold === undefined) return { text: 'N/A', color: 'text-gray-500', icon: <AlertCircle className="mr-1 h-4 w-4" /> };
    
    // Ensure threshold is treated as the point where score becomes anomalous
    // Assuming higher score = more anomalous as per typical ML model outputs for anomalies.
    // If lower score = more anomalous (like IsolationForest default), this logic needs inversion.
    // The prompt for sniffer.py said: "For IsolationForest, lower scores are more anomalous. The threshold is typically a negative value for anomalies."
    // And `is_anomaly = int(score < self.anomaly_threshold_value)`
    // So, if score < threshold, it's an anomaly.
    
    const isClearlyAnomaly = latestAnomaly?.is_anomaly === 1; // Rely on the backend's verdict primarily

    if (isClearlyAnomaly) {
        if (score < threshold * 0.8) return { text: 'Highly Malicious', color: 'text-red-600', icon: <ShieldAlert className="mr-1 h-4 w-4" /> };
        return { text: 'Likely Malicious', color: 'text-red-500', icon: <ShieldAlert className="mr-1 h-4 w-4" /> };
    }
    if (score < threshold * 1.2) { // Close to threshold but not marked as anomaly
        return { text: 'Borderline', color: 'text-yellow-500', icon: <AlertCircle className="mr-1 h-4 w-4" /> };
    }
    return { text: 'Likely Benign', color: 'text-green-500', icon: <ShieldCheck className="mr-1 h-4 w-4" /> };
};


  const anomalyScoreTimelineData = useMemo(() => {
    return [...anomalyHistory].reverse().map(anomaly => ({
      time: new Date(anomaly.timestamp).toLocaleTimeString(),
      score: anomaly.anomaly_score,
      threshold: anomaly.threshold,
    }));
  }, [anomalyHistory]);

  const featureRadarData = useMemo(() => {
    if (!latestAnomaly?.metadata?.features_contributing) return [];
    
    const features = latestAnomaly.metadata.features_contributing;
    // Select top 5-7 numerical features by magnitude or a predefined list
    // For simplicity, let's pick a few common ones expected from sniffer.py's EXPECTED_FEATURES
    // Normalization is crucial here. Assuming values are somewhat normalized or we pick features that don't vary too wildly.
    // A proper normalization (e.g., min-max scaling based on historical data or expected ranges) would be better.
    
    const selectedFeatureKeys = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 
        'Fwd Packet Length Max', 'Bwd Packet Length Max'
    ];

    let processedFeatures = [];
    let maxVal = 1; // Avoid division by zero, find actual max for normalization

    for(const key of selectedFeatureKeys) {
        if (features[key] !== undefined && typeof features[key] === 'number') {
            maxVal = Math.max(maxVal, Math.abs(features[key]));
        }
    }
    
    for (const key of selectedFeatureKeys) {
      const value = typeof features[key] === 'number' ? features[key] : 0;
      processedFeatures.push({
        subject: key.replace(/ /g, '\n'), // For better axis display
        value: (value / maxVal) * 100, // Normalize to 0-100 for radar
        fullMark: 100,
      });
    }
    return processedFeatures;

  }, [latestAnomaly]);

  const trendInsights = useMemo(() => {
    const insights = [];
    const historyCount = anomalyHistory.length;

    if (latestAnomaly) {
      const timeSinceLast = (new Date().getTime() - new Date(latestAnomaly.timestamp).getTime()) / (1000 * 60); // in minutes
      insights.push(`Last anomaly: ${timeSinceLast.toFixed(1)} min ago.`);
    }

    if (historyCount > 5) { // Need some history for trend
      const recentSliceTime = new Date(anomalyHistory[0].timestamp).getTime() - (5 * 60 * 1000); // Last 5 minutes
      const recentAnomalies = anomalyHistory.filter(a => new Date(a.timestamp).getTime() > recentSliceTime).length;
      // This is a simple count, a more complex % change would need a longer baseline.
      if (recentAnomalies > historyCount / 4) { // If more than 25% of history is in last 5 mins (and history is full)
          insights.push(`Activity Spike: ${recentAnomalies} anomalies in the last 5 mins.`);
      }
    }
    
    if (latestAnomaly?.source_ip) {
        const ipCount = anomalyHistory.filter(a => a.source_ip === latestAnomaly.source_ip).length;
        if (ipCount > 1) {
            insights.push(`Source IP ${latestAnomaly.source_ip} flagged ${ipCount} times recently.`);
        }
    }
    return insights;
  }, [anomalyHistory, latestAnomaly]);


  const copyFeaturesToClipboard = () => {
    if (latestAnomaly?.metadata?.features_contributing) {
      navigator.clipboard.writeText(JSON.stringify(latestAnomaly.metadata.features_contributing, null, 2))
        .then(() => { /* console.log('Features copied to clipboard'); */ })
        .catch(err => { /* console.error('Failed to copy features: ', err); */ });
    }
  };

  if (!latestAnomaly) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle>Anomaly Isolation Detail</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-64">
            <AlertCircle className="w-16 h-16 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Waiting for anomaly data...</p>
            <p className="text-sm text-muted-foreground">No anomalies detected recently.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const verdict = getVerdict(latestAnomaly.anomaly_score, latestAnomaly.threshold);

  return (
    <Card className="w-full animate-fade-in">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="text-2xl font-bold text-isimbi-purple">Latest Anomaly Detected</CardTitle>
            <CardDescription>Detailed breakdown of the most recent network anomaly.</CardDescription>
          </div>
          <Badge variant={latestAnomaly.is_anomaly === 1 ? "destructive" : "secondary"}>
            {latestAnomaly.is_anomaly === 1 ? "Anomaly Confirmed" : "Observation"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Anomaly Summary Section */}
        <Card className="bg-muted/30 border-l-4" style={{ borderColor: verdict.color }}>
          <CardHeader>
            <CardTitle className="flex items-center text-xl">
              {verdict.icon}
              Anomaly Summary: <span className={`ml-2 ${verdict.color}`}>{verdict.text}</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
            <div><strong>ID:</strong> {latestAnomaly.id}</div>
            <div><strong>Time:</strong> {new Date(latestAnomaly.timestamp).toLocaleString()}</div>
            <div><strong>Severity:</strong> {latestAnomaly.severity}</div>
            <div><strong>Score:</strong> {latestAnomaly.anomaly_score?.toFixed(4)}</div>
            <div><strong>Threshold:</strong> {latestAnomaly.threshold?.toFixed(4)}</div>
            <div><strong>Model:</strong> {latestAnomaly.metadata?.model_name || 'N/A'}</div>
            <div className="md:col-span-2"><strong>Flow:</strong> {latestAnomaly.source_ip} ({latestAnomaly.protocol}) &rarr; {latestAnomaly.destination_ip}:{latestAnomaly.destination_port}</div>
            <div className="md:col-span-3"><strong>Description:</strong> {latestAnomaly.description}</div>
          </CardContent>
        </Card>

        {/* Anomaly Score Timeline Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><BarChart className="mr-2 h-5 w-5 text-isimbi-purple" />Anomaly Score Timeline (Last {MAX_ANOMALY_HISTORY} Events)</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={anomalyScoreTimelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#444' : '#ccc'} />
                <XAxis dataKey="time" stroke={theme === 'dark' ? '#888' : '#666'} />
                <YAxis domain={[0, 'auto']} stroke={theme === 'dark' ? '#888' : '#666'} />
                <Tooltip
                  contentStyle={{ 
                    backgroundColor: theme === 'dark' ? 'hsl(var(--background))' : '#fff', 
                    borderColor: theme === 'dark' ? 'hsl(var(--border))' : '#ccc' 
                  }}
                  labelStyle={{ color: theme === 'dark' ? '#fff' : '#000' }}
                />
                <Legend />
                <Line type="monotone" dataKey="score" stroke="#8884d8" name="Anomaly Score" dot={{ r: 3 }} />
                {latestAnomaly.threshold !== undefined && (
                  <ReferenceLine y={latestAnomaly.threshold} label={{value: "Threshold", position:"insideTopRight", fill: theme === 'dark' ? '#aaa' : '#555' }} stroke="red" strokeDasharray="3 3" />
                )}
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Trend Insights */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center"><TrendingUp className="mr-2 h-5 w-5 text-isimbi-purple" />Trend Insights</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                    {trendInsights.length > 0 ? trendInsights.map((insight, idx) => (
                    <div key={idx} className="flex items-center">
                        <Target className="mr-2 h-4 w-4 text-muted-foreground flex-shrink-0" />
                        <span>{insight}</span>
                    </div>
                    )) : <p className="text-muted-foreground">Not enough data for trends yet.</p>}
                </CardContent>
            </Card>

            {/* Feature Contribution Radar Chart */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center"><BarChart className="mr-2 h-5 w-5 transform rotate-90 text-isimbi-purple" />Key Feature Contribution</CardTitle>
                </CardHeader>
                <CardContent className="h-72">
                {featureRadarData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                    <RadarChart cx="50%" cy="50%" outerRadius="80%" data={featureRadarData}>
                        <PolarGrid stroke={theme === 'dark' ? '#444' : '#ccc'} />
                        <PolarAngleAxis dataKey="subject" tick={{ fill: theme === 'dark' ? '#888' : '#666', fontSize: 10 }} />
                        <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: theme === 'dark' ? '#888' : '#666', fontSize: 10 }} />
                        <Radar name="Feature Value" dataKey="value" stroke="#8884d8" fill="#8884d8" fillOpacity={0.6} />
                        <Tooltip contentStyle={{ backgroundColor: theme === 'dark' ? 'hsl(var(--background))' : '#fff', borderColor: theme === 'dark' ? 'hsl(var(--border))' : '#ccc' }} />
                    </RadarChart>
                    </ResponsiveContainer>
                ) : (
                    <p className="text-muted-foreground text-center pt-10">No feature contribution data available or features not numerical.</p>
                )}
                </CardContent>
            </Card>
        </div>


        {/* Flow Metadata Panel */}
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
                <CardTitle className="flex items-center"><AlertCircle className="mr-2 h-5 w-5 text-isimbi-purple" />Contributing Features & Flow Metadata</CardTitle>
                <Button variant="outline" size="sm" onClick={copyFeaturesToClipboard}><Copy className="mr-2 h-4 w-4" />Copy JSON</Button>
            </div>
          </CardHeader>
          <CardContent>
            {latestAnomaly.metadata?.features_contributing && Object.keys(latestAnomaly.metadata.features_contributing).length > 0 ? (
              <ScrollArea className="h-72 w-full rounded-md border p-4 bg-muted/20 text-xs">
                <pre>{JSON.stringify(latestAnomaly.metadata.features_contributing, null, 2)}</pre>
              </ScrollArea>
            ) : (
              <p className="text-muted-foreground">No detailed features available for this anomaly.</p>
            )}
          </CardContent>
        </Card>

        {/* Action Section */}
        <CardFooter className="flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-2 pt-6">
            <Button variant="outline"><Send className="mr-2 h-4 w-4" />Send for Deeper Inspection</Button>
            <Button variant="outline" className="text-yellow-600 border-yellow-500 hover:bg-yellow-100 hover:text-yellow-700 dark:text-yellow-400 dark:border-yellow-600 dark:hover:bg-yellow-700/20 dark:hover:text-yellow-300">
                <ShieldCheck className="mr-2 h-4 w-4" />Label as False Positive
            </Button>
            <Button variant="destructive"><XCircle className="mr-2 h-4 w-4" />Block IP</Button>
        </CardFooter>
      </CardContent>
    </Card>
  );
};

export default AnomalyIsolationCard;

// Helper type for Recharts Radar data
interface RadarDataPoint {
  subject: string;
  value: number;
  fullMark: number;
}
