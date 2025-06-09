import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Download, Check, AlertTriangle, RefreshCw, Clock, Info, ArrowRight } from "lucide-react";
import Header from "../../components/layout/Header";
import { useToast } from "@/hooks/use-toast";

export const UpdatesPage = () => {
  const { toast } = useToast();
  const [isUpdating, setIsUpdating] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const handleUpdate = () => {
    setIsUpdating(true);
    setProgress(0);
    
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsUpdating(false);
          toast({
            title: "Update complete",
            description: "System has been updated to v2.4.1",
          });
          return 100;
        }
        return prev + 5;
      });
    }, 300);
  };
  
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header />
      
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">System Updates</h1>
              <p className="text-muted-foreground">Check for and apply system updates</p>
            </div>
            
            <Button onClick={() => toast({ title: "Checking for updates" })} variant="outline">
              <RefreshCw className="mr-2 h-4 w-4" />
              Check for Updates
            </Button>
          </div>
          
          <div className="space-y-6">
            {/* Current Version */}
            <Card>
              <CardHeader>
                <CardTitle>Current System Version</CardTitle>
                <CardDescription>Information about your current installation</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <div className="text-sm font-medium">Version</div>
                      <div>2.3.8</div>
                    </div>
                    <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/20">
                      <Check className="mr-1 h-3 w-3" /> Up to date
                    </Badge>
                  </div>
                  
                  <Separator />
                  
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    <div>
                      <div className="text-sm font-medium text-muted-foreground">Installed On</div>
                      <div>March 15, 2025</div>
                    </div>
                    <div>
                      <div className="text-sm font-medium text-muted-foreground">Last Updated</div>
                      <div>May 2, 2025</div>
                    </div>
                    <div>
                      <div className="text-sm font-medium text-muted-foreground">Build Number</div>
                      <div>23809-RC1</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            {/* Available Updates */}
            <Card>
              <CardHeader>
                <CardTitle>Available Updates</CardTitle>
                <CardDescription>Updates ready to be installed</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-lg font-medium flex items-center">
                        Security Update (v2.4.1)
                        <Badge className="ml-2 bg-red-500/10 text-red-500 border-red-500/20">Security</Badge>
                      </h3>
                      <p className="text-muted-foreground">Addresses critical security vulnerabilities</p>
                      <div className="flex items-center mt-1 text-sm text-muted-foreground">
                        <Clock className="mr-1 h-3.5 w-3.5" />
                        <span>Released: May 13, 2025</span>
                      </div>
                    </div>
                    
                    <Button onClick={handleUpdate} disabled={isUpdating}>
                      {isUpdating ? (
                        <>
                          <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                          Updating...
                        </>
                      ) : (
                        <>
                          <Download className="mr-2 h-4 w-4" />
                          Install Update
                        </>
                      )}
                    </Button>
                  </div>
                  
                  {isUpdating && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Downloading and installing update...</span>
                        <span>{progress}%</span>
                      </div>
                      <Progress value={progress} className="h-2" />
                    </div>
                  )}
                  
                  <Separator />
                  
                  <div>
                    <h4 className="font-medium mb-2">What's included:</h4>
                    <ul className="space-y-2 text-sm">
                      <li className="flex">
                        <AlertTriangle className="h-4 w-4 text-red-500 mr-2 flex-shrink-0" />
                        <span>Fixes critical vulnerability in authentication module (CVE-2025-1234)</span>
                      </li>
                      <li className="flex">
                        <AlertTriangle className="h-4 w-4 text-amber-500 mr-2 flex-shrink-0" />
                        <span>Addresses session handling weakness in API endpoints</span>
                      </li>
                      <li className="flex">
                        <Check className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
                        <span>Performance improvements for log processing</span>
                      </li>
                      <li className="flex">
                        <Check className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" />
                        <span>Updated dependencies to latest secure versions</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            {/* Update History */}
            <Card>
              <CardHeader>
                <CardTitle>Update History</CardTitle>
                <CardDescription>Previously installed updates</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    {
                      version: "v2.3.8",
                      date: "May 2, 2025",
                      type: "maintenance",
                      notes: "Performance optimizations and bug fixes"
                    },
                    {
                      version: "v2.3.5",
                      date: "April 12, 2025",
                      type: "security",
                      notes: "Security patches for log4j vulnerability"
                    },
                    {
                      version: "v2.3.0",
                      date: "March 15, 2025",
                      type: "feature",
                      notes: "Added threat intelligence integration"
                    }
                  ].map((update, i) => (
                    <div key={i} className="flex items-start justify-between pb-4 border-b last:border-0 last:pb-0">
                      <div>
                        <div className="flex items-center">
                          <h4 className="font-medium">{update.version}</h4>
                          <Badge className={`ml-2 ${
                            update.type === 'security' ? 'bg-red-500/10 text-red-500 border-red-500/20' :
                            update.type === 'feature' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' :
                            'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                          }`}>
                            {update.type.charAt(0).toUpperCase() + update.type.slice(1)}
                          </Badge>
                        </div>
                        <div className="text-sm text-muted-foreground mt-1">{update.date}</div>
                        <div className="mt-1">{update.notes}</div>
                      </div>
                      <Button variant="ghost" size="sm">
                        <Info className="h-4 w-4 mr-1" />
                        Details
                      </Button>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="outline" className="w-full" onClick={() => toast({ title: "Viewing full update history" })}>
                  View Complete History
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UpdatesPage;
