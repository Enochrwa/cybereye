
import React, { useState } from 'react';
import { 
  User, Clock, Calendar, Search, Filter, RefreshCcw, AlertTriangle, 
  ChevronDown, Activity, Shield, UserCheck, FileBarChart, Check
} from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useTheme } from "@/components/theme/ThemeProvider";

const UserBehaviorAnalysis = () => {
  const { theme } = useTheme();
  const [selectedUser, setSelectedUser] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('7d');
  
  const users = [
    { id: 'admin', name: 'Administrator', role: 'System Admin', riskScore: 12 },
    { id: 'john.doe', name: 'John Doe', role: 'Developer', riskScore: 25 },
    { id: 'jane.smith', name: 'Jane Smith', role: 'Security Analyst', riskScore: 8 },
    { id: 'bob.johnson', name: 'Bob Johnson', role: 'Database Admin', riskScore: 45 },
    { id: 'alice.wong', name: 'Alice Wong', role: 'Network Admin', riskScore: 17 }
  ];
  
  // Get color based on risk score
  const getRiskScoreColor = (score: number): string => {
    if (score < 15) return 'text-green-500';
    if (score < 30) return 'text-amber-500';
    return 'text-red-500';
  };
  
  // Get gradient color for user card based on risk score
  const getUserCardGradient = (score: number): string => {
    if (score < 15) return 'from-green-500/5 to-green-500/10';
    if (score < 30) return 'from-amber-500/5 to-amber-500/10';
    return 'from-red-500/5 to-red-500/10';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium flex items-center">
          <Shield className="h-5 w-5 mr-2 text-isimbi-purple" />
          User Behavior Analysis
        </h3>
        <div className="flex items-center gap-2">
          <div className="flex bg-muted rounded-md p-1">
            <Button variant={timeRange === '1d' ? "default" : "ghost"} size="sm" className="h-8 text-xs" onClick={() => setTimeRange('1d')}>24h</Button>
            <Button variant={timeRange === '7d' ? "default" : "ghost"} size="sm" className="h-8 text-xs" onClick={() => setTimeRange('7d')}>7d</Button>
            <Button variant={timeRange === '30d' ? "default" : "ghost"} size="sm" className="h-8 text-xs" onClick={() => setTimeRange('30d')}>30d</Button>
          </div>
          <Button size="sm" className="h-9 gap-1">
            <RefreshCcw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>
      
      {/* User Selection */}
      <div className="grid grid-cols-5 gap-4">
        {users.map(user => (
          <div 
            key={user.id}
            className={`border rounded-md p-4 cursor-pointer hover:border-primary transition-all duration-300 shadow-sm hover:shadow-md ${
              selectedUser === user.id ? 'border-primary bg-primary/5' : ''
            } bg-gradient-to-br ${getUserCardGradient(user.riskScore)}`}
            onClick={() => setSelectedUser(user.id)}
          >
            <div className="flex justify-between items-start">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-full bg-primary/20 flex items-center justify-center">
                  <User className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <div className="font-medium">{user.name}</div>
                  <div className="text-xs text-muted-foreground">{user.role}</div>
                </div>
              </div>
              <Badge 
                variant="outline"
                className={`${
                  user.riskScore < 15 ? 'bg-green-500/20 text-green-500 border-green-500/30' : 
                  user.riskScore < 30 ? 'bg-amber-500/20 text-amber-500 border-amber-500/30' : 
                  'bg-red-500/20 text-red-500 border-red-500/30'
                } hover:${
                  user.riskScore < 15 ? 'bg-green-500/30' : 
                  user.riskScore < 30 ? 'bg-amber-500/30' : 
                  'bg-red-500/30'
                }`}
              >
                {user.riskScore}
              </Badge>
            </div>
          </div>
        ))}
      </div>
      
      {/* Activity Heatmap */}
      <div className="border rounded-lg p-5 glass-card">
        <div className="flex justify-between items-center mb-4">
          <h4 className="text-sm font-medium flex items-center gap-2">
            <Clock className="h-4 w-4 text-isimbi-purple" />
            Activity Heatmap
          </h4>
          <Button variant="outline" size="sm" className="h-8 text-xs">
            <Calendar className="h-4 w-4 mr-2" />
            Change Date Range
          </Button>
        </div>
        
        {/* This would be replaced with an actual heatmap chart */}
        <div className="bg-muted h-[200px] rounded-md flex items-center justify-center relative overflow-hidden">
          <div className="absolute inset-0 opacity-20 bg-gradient-to-br from-isimbi-purple/20 to-isimbi-purple/5"></div>
          <span className="text-muted-foreground flex items-center gap-2">
            <FileBarChart className="h-5 w-5" />
            User activity heatmap would appear here
          </span>
        </div>
      </div>
      
      {/* Behavior Graphs */}
      <div className="grid grid-cols-2 gap-6">
        {/* Login Patterns */}
        <div className="border rounded-lg p-5 glass-card">
          <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
            <UserCheck className="h-4 w-4 text-isimbi-purple" />
            Login Patterns
          </h4>
          <div className="bg-muted h-[200px] rounded-md flex items-center justify-center relative overflow-hidden">
            <div className="absolute inset-0 opacity-20 bg-gradient-to-br from-blue-500/20 to-blue-500/5"></div>
            <span className="text-muted-foreground">Login pattern graph would appear here</span>
          </div>
        </div>
        
        {/* Working Hours */}
        <div className="border rounded-lg p-5 glass-card">
          <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
            <Clock className="h-4 w-4 text-isimbi-purple" />
            Working Hours
          </h4>
          <div className="bg-muted h-[200px] rounded-md flex items-center justify-center relative overflow-hidden">
            <div className="absolute inset-0 opacity-20 bg-gradient-to-br from-purple-500/20 to-purple-500/5"></div>
            <span className="text-muted-foreground">Working hours chart would appear here</span>
          </div>
        </div>
      </div>
      
      {/* Behavior Deviation Graph */}
      <div className="border rounded-lg p-5 shadow-sm glass-card">
        <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
          <Activity className="h-4 w-4 text-isimbi-purple" />
          Behavioral Deviation Analysis
        </h4>
        <div className="bg-muted h-[200px] rounded-md flex items-center justify-center relative overflow-hidden">
          <div className="absolute inset-0 opacity-20 bg-gradient-to-br from-isimbi-purple/20 to-isimbi-purple/5"></div>
          <span className="text-muted-foreground">Behavior deviation graph would appear here</span>
        </div>
        <div className="mt-4 text-xs text-muted-foreground p-3 bg-background/50 border rounded-md">
          <p>Baseline user behavior model is compared against current activity patterns to detect anomalies and unusual behavior changes over time.</p>
        </div>
      </div>
      
      {/* User Behavior Details */}
      <div className="border rounded-lg overflow-hidden shadow-sm">
        <div className="flex justify-between items-center p-4 border-b bg-muted/30">
          <h4 className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-isimbi-purple" />
            Behavior Analytics
          </h4>
          <Button variant="outline" size="sm" className="gap-1">
            <FileBarChart className="h-4 w-4 mr-1" />
            Export Data
          </Button>
        </div>
        
        <div className="p-5">
          <div className="space-y-6">
            <div className="grid grid-cols-4 gap-4">
              <div className="p-4 border rounded-lg bg-card/70 backdrop-blur-sm shadow-sm hover:shadow-md transition-all duration-300">
                <div className="text-sm font-medium text-muted-foreground">Risk Score</div>
                <div className={`text-2xl font-bold mt-1 ${
                  selectedUser === 'all' ? 'text-isimbi-purple' : 
                  getRiskScoreColor(users.find(u => u.id === selectedUser)?.riskScore || 0)
                }`}>
                  {selectedUser === 'all' ? 
                    Math.round(users.reduce((sum, user) => sum + user.riskScore, 0) / users.length) : 
                    users.find(u => u.id === selectedUser)?.riskScore || 0}
                </div>
              </div>
              
              <div className="p-4 border rounded-lg bg-card/70 backdrop-blur-sm shadow-sm hover:shadow-md transition-all duration-300">
                <div className="text-sm font-medium text-muted-foreground">Failed Logins</div>
                <div className="text-2xl font-bold mt-1 text-amber-500">
                  {Math.floor(Math.random() * 5)}
                </div>
              </div>
              
              <div className="p-4 border rounded-lg bg-card/70 backdrop-blur-sm shadow-sm hover:shadow-md transition-all duration-300">
                <div className="text-sm font-medium text-muted-foreground">Off-hours Activity</div>
                <div className="text-2xl font-bold mt-1 text-blue-500">
                  {Math.floor(Math.random() * 20)}%
                </div>
              </div>
              
              <div className="p-4 border rounded-lg bg-card/70 backdrop-blur-sm shadow-sm hover:shadow-md transition-all duration-300">
                <div className="text-sm font-medium text-muted-foreground">File Operations</div>
                <div className="text-2xl font-bold mt-1 text-isimbi-purple">
                  {Math.floor(Math.random() * 200) + 50}
                </div>
              </div>
            </div>
            
            {/* Behavior Anomalies */}
            <div>
              <div className="text-sm font-medium mb-2 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                Detected Anomalies
              </div>
              <ScrollArea className="h-[240px] border rounded-lg p-2">
                <div className="space-y-3 p-2">
                  {selectedUser !== 'bob.johnson' ? (
                    <div className="border rounded-md p-4 text-sm bg-green-500/5 border-green-500/20 flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-green-500/20 flex items-center justify-center">
                        <Check className="h-4 w-4 text-green-500" />
                      </div>
                      <span>No significant behavioral anomalies detected for this user.</span>
                    </div>
                  ) : (
                    <>
                      <div className="border border-amber-200 bg-amber-50/50 dark:bg-amber-950/20 dark:border-amber-800/30 rounded-md p-4 animate-fade-in">
                        <div className="flex items-start gap-3">
                          <div className="h-8 w-8 rounded-full bg-amber-500/20 flex items-center justify-center mt-0.5">
                            <AlertTriangle className="h-4 w-4 text-amber-600" />
                          </div>
                          <div>
                            <div className="font-medium text-amber-800 dark:text-amber-400">Unusual Login Time</div>
                            <div className="text-sm text-amber-700 dark:text-amber-300">Login at 2:34 AM outside of normal working hours</div>
                            <div className="text-xs text-amber-600 dark:text-amber-300/80 mt-2 flex items-center gap-2">
                              <Clock className="h-3 w-3" /> 3 days ago
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="border border-amber-200 bg-amber-50/50 dark:bg-amber-950/20 dark:border-amber-800/30 rounded-md p-4 animate-fade-in" style={{ animationDelay: '0.1s' }}>
                        <div className="flex items-start gap-3">
                          <div className="h-8 w-8 rounded-full bg-amber-500/20 flex items-center justify-center mt-0.5">
                            <AlertTriangle className="h-4 w-4 text-amber-600" />
                          </div>
                          <div>
                            <div className="font-medium text-amber-800 dark:text-amber-400">Unusual File Access Pattern</div>
                            <div className="text-sm text-amber-700 dark:text-amber-300">Accessed 45 user data files in 3 minutes</div>
                            <div className="text-xs text-amber-600 dark:text-amber-300/80 mt-2 flex items-center gap-2">
                              <Clock className="h-3 w-3" /> Yesterday at 4:15 PM
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="border border-red-200 bg-red-50/50 dark:bg-red-950/20 dark:border-red-800/30 rounded-md p-4 pulse-border animate-fade-in" style={{ animationDelay: '0.2s' }}>
                        <div className="flex items-start gap-3">
                          <div className="h-8 w-8 rounded-full bg-red-500/20 flex items-center justify-center mt-0.5">
                            <AlertTriangle className="h-4 w-4 text-red-600" />
                          </div>
                          <div>
                            <div className="font-medium text-red-800 dark:text-red-400">Privilege Escalation</div>
                            <div className="text-sm text-red-700 dark:text-red-300">Unusual sudo usage to access system files</div>
                            <div className="text-xs text-red-600 dark:text-red-300/80 mt-2 flex items-center gap-2">
                              <Clock className="h-3 w-3" /> Today at 10:23 AM
                            </div>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </ScrollArea>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserBehaviorAnalysis;
