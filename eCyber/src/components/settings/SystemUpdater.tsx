
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { RefreshCw, Download, CheckCircle, AlertCircle } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

const SystemUpdater = () => {
  const [isChecking, setIsChecking] = useState(false);
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [progress, setProgress] = useState(0);
  const { toast } = useToast();

  const checkForUpdates = () => {
    setIsChecking(true);
    toast({
      title: "Checking for Updates",
      description: "Searching for system updates...",
    });
    
    // Simulate checking for updates
    setTimeout(() => {
      setIsChecking(false);
      
      // Randomly determine if an update is available (for demo)
      const hasUpdate = Math.random() > 0.5;
      setUpdateAvailable(hasUpdate);
      
      if (hasUpdate) {
        toast({
          title: "Update Available",
          description: "A new system update is available (v1.5.0)",
        });
      } else {
        toast({
          title: "System Up to Date",
          description: "You are running the latest version (v1.4.2)",
        });
      }
    }, 2000);
  };
  
  const installUpdate = () => {
    setIsUpdating(true);
    setProgress(0);
    
    toast({
      title: "Installing Update",
      description: "Starting installation process...",
    });
    
    // Simulate update progress
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setTimeout(() => {
            setIsUpdating(false);
            setUpdateAvailable(false);
            toast({
              title: "Update Complete",
              description: "System successfully updated to v1.5.0",
            });
          }, 500);
          return 100;
        }
        return prev + 5;
      });
    }, 300);
  };
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center">
          <RefreshCw className="mr-2" size={16} />
          System Information
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm text-muted-foreground">Version</div>
              <div className="flex items-center">
                {updateAvailable ? "eCyber v1.0.0" : "eCyber v1.0.1"} 
                {updateAvailable ? (
                  <Badge className="ml-2 bg-amber-500/10 text-amber-500">Update Available</Badge>
                ) : (
                  <Badge className="ml-2 bg-green-500/10 text-green-500">Latest</Badge>
                )}
              </div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Last Updated</div>
              <div>{updateAvailable ? "May 1, 2025" : new Date().toLocaleDateString()}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Deployment</div>
              <div>On-Premise</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">License</div>
              <div className="flex items-center">
                Enterprise <Badge className="ml-2 bg-green-500/10 text-green-500">Active</Badge>
              </div>
            </div>
          </div>
          
          {isUpdating ? (
            <div className="space-y-2 pt-4 border-t border-border">
              <div className="flex justify-between mb-1">
                <span className="text-sm">Installing update to v1.5.0...</span>
                <span className="text-sm">{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
              {progress < 100 ? (
                <div className="text-xs text-muted-foreground">Please don't close the application during update</div>
              ) : (
                <div className="flex items-center text-green-500 text-sm">
                  <CheckCircle className="mr-1 h-4 w-4" />
                  Update complete!
                </div>
              )}
            </div>
          ) : updateAvailable ? (
            <div className="pt-4 border-t border-border space-y-3">
              <div className="flex items-center text-sm">
                <AlertCircle className="mr-2 h-4 w-4 text-amber-500" />
                <span>Update available: eCyber v1.1.0</span>
              </div>
              <div className="flex space-x-2">
                <Button variant="outline" onClick={checkForUpdates} disabled={isChecking}>
                  <RefreshCw className={`mr-2 h-4 w-4 ${isChecking ? 'animate-spin' : ''}`} />
                  {isChecking ? 'Checking...' : 'Check Again'}
                </Button>
                <Button onClick={installUpdate}>
                  <Download className="mr-2 h-4 w-4" />
                  Install Update
                </Button>
              </div>
            </div>
          ) : (
            <div className="pt-4 border-t border-border">
              <Button variant="outline" onClick={checkForUpdates} disabled={isChecking}>
                <RefreshCw className={`mr-2 h-4 w-4 ${isChecking ? 'animate-spin' : ''}`} />
                {isChecking ? 'Checking...' : 'Check for Updates'}
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default SystemUpdater;
