
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search, AlertTriangle, Check, File, HardDrive, Database, Server, Shield } from 'lucide-react';
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";

interface ScanResult {
  id: string;
  path: string;
  type: 'file' | 'system' | 'memory' | 'registry';
  status: 'clean' | 'suspicious' | 'infected';
  threat?: string;
  action?: 'quarantine' | 'delete' | 'ignore';
}

const ManualScanComponent = () => {
  const { toast } = useToast();
  const [scanning, setScanning] = useState(false);
  const [scanType, setScanType] = useState('quick');
  const [progress, setProgress] = useState(0);
  const [currentItem, setCurrentItem] = useState('');
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  
  // File paths for the scan simulation
  const filePaths = [
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\Program Files\\Common Files\\System\\ado\\msado15.dll',
    'C:\\Users\\Administrator\\Downloads\\invoice_april2025.pdf',
    'C:\\Users\\Administrator\\Documents\\financial_report.xlsx',
    'C:\\Windows\\System32\\svchost.exe',
    'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE',
    'C:\\Users\\Administrator\\AppData\\Local\\Temp\\temp_3821.exe',
    'C:\\Users\\Administrator\\Downloads\\update_installer.exe',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
    'Memory process: chrome.exe (PID: 4872)',
    'Memory process: explorer.exe (PID: 2340)',
    'Memory process: svchost.exe (PID: 892)',
    'Memory process: unknown.exe (PID: 7231)',
  ];
  
  // Simulate threats for some files
  const threatPatterns = [
    { pattern: 'temp_3821.exe', threat: 'Trojan.GenericKD.12829021', probability: 0.95 },
    { pattern: 'update_installer.exe', threat: 'Potentially Unwanted Program', probability: 0.7 },
    { pattern: 'unknown.exe', threat: 'Suspicious Memory Modification', probability: 0.8 },
    { pattern: 'RunMRU', threat: 'Suspicious Registry Modification', probability: 0.5 },
  ];
  
  const startScan = () => {
    setScanning(true);
    setProgress(0);
    setScanResults([]);
    setCurrentItem('');
    
    toast({
      title: "Scan Started",
      description: `Starting ${scanType} scan of system`,
      variant: "default"
    });
    
    // Determine how many files to scan based on scan type
    const totalFiles = scanType === 'quick' ? 8 : scanType === 'full' ? filePaths.length : 4;
    let currentIndex = 0;
    
    const scanInterval = setInterval(() => {
      if (currentIndex >= totalFiles) {
        clearInterval(scanInterval);
        setScanning(false);
        setProgress(100);
        setCurrentItem('Scan complete');
        
        // Show completion toast with results
        const infectedCount = scanResults.filter(r => r.status === 'infected').length;
        const suspiciousCount = scanResults.filter(r => r.status === 'suspicious').length;
        
        toast({
          title: "Scan Complete",
          description: `Found ${infectedCount} infections and ${suspiciousCount} suspicious items`,
          variant: infectedCount > 0 ? "destructive" : "default"
        });
        
        return;
      }
      
      // Get the current file to scan
      const fileIndex = Math.min(currentIndex, filePaths.length - 1);
      const currentFile = filePaths[fileIndex];
      setCurrentItem(currentFile);
      
      // Update progress
      setProgress(Math.round((currentIndex / totalFiles) * 100));
      
      // Check if this file matches any threat patterns
      const matchedThreat = threatPatterns.find(threat => 
        currentFile.includes(threat.pattern) && Math.random() <= threat.probability
      );
      
      // Determine file type
      let fileType: 'file' | 'system' | 'memory' | 'registry' = 'file';
      if (currentFile.startsWith('HKEY_')) {
        fileType = 'registry';
      } else if (currentFile.startsWith('Memory')) {
        fileType = 'memory';
      } else if (currentFile.includes('System32') || currentFile.includes('Program Files')) {
        fileType = 'system';
      }
      
      // Create scan result
      if (matchedThreat) {
        const newResult: ScanResult = {
          id: `scan-${Date.now()}-${currentIndex}`,
          path: currentFile,
          type: fileType,
          status: Math.random() > 0.3 ? 'infected' : 'suspicious',
          threat: matchedThreat.threat
        };
        
        setScanResults(prev => [...prev, newResult]);
        
        // Show alert for infected files
        if (newResult.status === 'infected') {
          toast({
            title: `Infection Found: ${matchedThreat.threat}`,
            description: `Located in: ${currentFile}`,
            variant: "destructive"
          });
        }
      } else if (Math.random() > 0.85) {
        // Small chance of random suspicious item
        setScanResults(prev => [...prev, {
          id: `scan-${Date.now()}-${currentIndex}`,
          path: currentFile,
          type: fileType,
          status: 'suspicious',
          threat: 'Unusual file behavior'
        }]);
      }
      
      currentIndex++;
    }, scanType === 'quick' ? 800 : 500);
    
    return () => clearInterval(scanInterval);
  };
  
  const handleAction = (id: string, action: 'quarantine' | 'delete' | 'ignore') => {
    setScanResults(prev => prev.map(result => 
      result.id === id ? { ...result, action } : result
    ));
    
    const result = scanResults.find(r => r.id === id);
    if (result) {
      toast({
        title: `${action === 'quarantine' ? 'Quarantined' : action === 'delete' ? 'Deleted' : 'Ignored'}: ${result.path}`,
        description: action === 'ignore' ? 'Item will remain on system' : 'Threat has been neutralized',
        variant: action === 'ignore' ? "default" : "default"
      });
    }
  };
  
  const getStatusBadge = (status: 'clean' | 'suspicious' | 'infected') => {
    switch (status) {
      case 'clean':
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">Clean</Badge>;
      case 'suspicious':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Suspicious</Badge>;
      case 'infected':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Infected</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };
  
  const getTypeIcon = (type: 'file' | 'system' | 'memory' | 'registry') => {
    switch (type) {
      case 'file':
        return <File size={16} className="text-blue-500" />;
      case 'system':
        return <Server size={16} className="text-amber-500" />;
      case 'memory':
        return <HardDrive size={16} className="text-purple-500" />;
      case 'registry':
        return <Database size={16} className="text-green-500" />;
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="h-5 w-5 text-isimbi-purple" />
          Manual System Scan
        </CardTitle>
        <CardDescription>Scan system for threats and vulnerabilities</CardDescription>
      </CardHeader>
      
      <CardContent className="p-6">
        {!scanning && progress === 0 ? (
          <>
            <div className="mb-6 space-y-4">
              <div className="space-y-2">
                <div className="font-medium text-sm mb-2">Select Scan Type</div>
                <Select defaultValue={scanType} onValueChange={setScanType}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select scan type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="targeted">Targeted Scan</SelectItem>
                    <SelectItem value="full">Full System Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              {scanType === 'targeted' && (
                <div className="space-y-2">
                  <div className="font-medium text-sm mb-2">Select Target Directory</div>
                  <div className="flex gap-2">
                    <Input placeholder="C:\Users\Administrator\Downloads" className="flex-1" />
                    <Button variant="outline">Browse</Button>
                  </div>
                </div>
              )}
              
              <div className="pt-2">
                <Button onClick={startScan} className="w-full">Start Scan</Button>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-muted/30">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-5 w-5 text-isimbi-purple" />
                <span className="font-medium">Last Scan Results</span>
              </div>
              {scanResults.length > 0 ? (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span>Scan completed:</span>
                    <span>Just now</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Items scanned:</span>
                    <span>{scanType === 'quick' ? '8' : scanType === 'full' ? '14' : '4'} files</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Threats detected:</span>
                    <span className="font-medium text-red-500">
                      {scanResults.filter(r => r.status === 'infected').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Suspicious items:</span>
                    <span className="font-medium text-amber-500">
                      {scanResults.filter(r => r.status === 'suspicious').length}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="text-center text-sm text-muted-foreground">
                  No recent scan results
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="space-y-4">
            {/* Scan progress */}
            <div className="space-y-2">
              <div className="flex justify-between text-sm mb-1">
                <span>{scanning ? 'Scanning...' : 'Scan complete'}</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="h-2" />
              {scanning && (
                <div className="text-xs text-muted-foreground truncate">
                  Scanning: {currentItem}
                </div>
              )}
            </div>
            
            {/* Live results */}
            <div className="border rounded-md">
              <div className="bg-muted p-2 font-medium text-sm">
                Scan Results
              </div>
              <div className="divide-y max-h-[300px] overflow-auto">
                {scanResults.length > 0 ? (
                  scanResults.map((result) => (
                    <div key={result.id} className="p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {getTypeIcon(result.type)}
                          <span className="font-medium text-sm truncate max-w-[200px]" title={result.path}>
                            {result.path.split('\\').pop()}
                          </span>
                        </div>
                        {getStatusBadge(result.status)}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1 mb-2">
                        {result.path}
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="text-xs font-medium">
                          {result.threat || 'Unknown threat'}
                        </div>
                        {!result.action && (
                          <div className="flex gap-1">
                            <Button 
                              size="sm" 
                              variant="destructive" 
                              className="h-7 text-xs"
                              onClick={() => handleAction(result.id, 'delete')}
                            >
                              Delete
                            </Button>
                            <Button 
                              size="sm" 
                              variant="outline" 
                              className="h-7 text-xs"
                              onClick={() => handleAction(result.id, 'quarantine')}
                            >
                              Quarantine
                            </Button>
                            <Button 
                              size="sm" 
                              variant="ghost" 
                              className="h-7 text-xs"
                              onClick={() => handleAction(result.id, 'ignore')}
                            >
                              Ignore
                            </Button>
                          </div>
                        )}
                        {result.action && (
                          <Badge variant={
                            result.action === 'delete' ? 'destructive' : 
                            result.action === 'quarantine' ? 'outline' : 
                            'secondary'
                          }>
                            {result.action === 'delete' ? 'Deleted' : 
                             result.action === 'quarantine' ? 'Quarantined' : 
                             'Ignored'}
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))
                ) : scanning ? (
                  <div className="p-8 text-center">
                    <div className="flex justify-center mb-3">
                      <Search className="animate-pulse text-muted-foreground" size={32} />
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Scanning system for threats...
                    </div>
                  </div>
                ) : (
                  <div className="p-8 text-center">
                    <div className="flex justify-center mb-3">
                      <Check className="text-green-500" size={32} />
                    </div>
                    <div className="text-sm font-medium">
                      No threats detected
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Your system is clean and secure
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        {scanning ? (
          <Button 
            variant="outline" 
            onClick={() => setScanning(false)} 
            className="w-full"
          >
            Cancel Scan
          </Button>
        ) : progress === 100 ? (
          <Button 
            variant="default" 
            onClick={() => {
              setProgress(0);
              setCurrentItem('');
            }} 
            className="w-full"
          >
            New Scan
          </Button>
        ) : (
          <Button 
            onClick={startScan} 
            className="w-full"
            disabled={scanning}
          >
            Scan System
          </Button>
        )}
      </CardFooter>
    </Card>
  );
};

export default ManualScanComponent;
