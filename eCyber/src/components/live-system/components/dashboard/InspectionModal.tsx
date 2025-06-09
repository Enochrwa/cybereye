import React from "react";
import { AlertTriangle, Check, Shield, FileTerminal, Cpu, Database, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ProcessItem, NetworkConnection } from "../../lib/socket";

interface InspectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  item: ProcessItem | NetworkConnection | null;
  type: "process" | "connection";
}

export function InspectionModal({ isOpen, onClose, item, type }: InspectionModalProps) {
  if (!item) return null;

  // Helper function to determine if the item is a process
  const isProcess = (item: ProcessItem | NetworkConnection): item is ProcessItem => {
    return type === "process";
  };

  // Helper function to determine if the item is a connection
  const isConnection = (item: ProcessItem | NetworkConnection): item is NetworkConnection => {
    return type === "connection";
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl bg-background/95 backdrop-blur-sm border-border/50 shadow-2xl overflow-y-auto" style={{ maxHeight: "90vh" }}>
        <DialogHeader>
          <DialogTitle className="text-xl flex items-center gap-2">
            {isProcess(item) ? (
              <>
                <FileTerminal className="h-5 w-5 text-cyber-chart-purple" />
                Process Inspection: {item.name}
              </>
            ) : (
              <>
                <Network className="h-5 w-5 text-cyber-chart-purple" />
                Connection Inspection: {isConnection(item) ? `${item.localAddress} → ${item.remoteAddress}` : ""}
              </>
            )}
          </DialogTitle>
          <DialogDescription>
            {isProcess(item) && (
              <div className="flex items-center gap-2">
                <Badge variant={item.suspicious ? "destructive" : "outline"}>
                  PID: {item.pid}
                </Badge>
                <Badge variant="outline" className="bg-background/50">
                  User: {item.user}
                </Badge>
                {item.status && (
                  <Badge
                    variant="outline"
                    className={cn(
                      item.status === "running" ? "bg-cyber-alert-green/20 text-cyber-alert-green border-cyber-alert-green/30" :
                      item.status === "sleeping" ? "bg-cyber-alert-blue/20 text-cyber-alert-blue border-cyber-alert-blue/30" :
                      "bg-muted/20 text-muted-foreground"
                    )}
                  >
                    {item.status}
                  </Badge>
                )}
              </div>
            )}
            
            {isConnection(item) && (
              <div className="flex items-center gap-2">
                <Badge variant={item.suspicious ? "destructive" : "outline"}>
                  PID: {item.pid}
                </Badge>
                <Badge
                  variant="outline"
                  className={cn(
                    item.status === "ESTABLISHED" ? "bg-cyber-alert-green/20 text-cyber-alert-green border-cyber-alert-green/30" :
                    item.status === "LISTENING" ? "bg-cyber-alert-blue/20 text-cyber-alert-blue border-cyber-alert-blue/30" :
                    "bg-muted/20 text-muted-foreground"
                  )}
                >
                  {item.status}
                </Badge>
              </div>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 gap-6 py-2">
          {/* Security Status */}
          <div className="space-y-3">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Security Status
            </h3>
            <div className="rounded-md bg-card p-4 border border-border/50">
              <div className="flex items-center justify-center">
                <div className={cn(
                  "h-24 w-24 rounded-full flex items-center justify-center",
                  (isProcess(item) && item.suspicious) || (isConnection(item) && item.suspicious)
                    ? "bg-destructive/10 text-destructive"
                    : "bg-cyber-alert-green/10 text-cyber-alert-green"
                )}>
                  {(isProcess(item) && item.suspicious) || (isConnection(item) && item.suspicious) ? (
                    <AlertTriangle className="h-10 w-10" />
                  ) : (
                    <Check className="h-10 w-10" />
                  )}
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                {isProcess(item) && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Signature:</span>
                      <span>{item.signed === null ? "Unknown" : item.signed ? "Verified" : "Not Signed"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Suspicion Level:</span>
                      <span className={item.suspicious ? "text-cyber-alert-red" : "text-cyber-alert-green"}>
                        {item.suspicious ? "High" : "Low"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Integrity:</span>
                      <span>Not Verified</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Privileges:</span>
                      <span>{item.user.includes("SYSTEM") ? "High" : "Standard"}</span>
                    </div>
                  </>
                )}

                {isConnection(item) && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Connection Type:</span>
                      <span>{item.isInternal ? "Internal" : "External"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Suspicion Level:</span>
                      <span className={item.suspicious ? "text-cyber-alert-red" : "text-cyber-alert-green"}>
                        {item.suspicious ? "High" : "Low"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Encryption:</span>
                      <span>Unknown</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Protocol:</span>
                      <span>TCP</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Resource Usage or Connection Details */}
          <div className="space-y-3">
            <h3 className="text-sm font-medium flex items-center gap-2">
              {isProcess(item) ? (
                <>
                  <Cpu className="h-4 w-4 text-muted-foreground" />
                  Resource Usage
                </>
              ) : (
                <>
                  <Network className="h-4 w-4 text-muted-foreground" />
                  Connection Details
                </>
              )}
            </h3>
            <div className="rounded-md bg-card p-4 border border-border/50">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                {isProcess(item) && (
                  <>
                    <div>
                      <div className="mb-1 flex justify-between">
                        <span className="text-muted-foreground">CPU Usage:</span>
                        <span className={item.cpu > 70 ? "text-cyber-alert-amber" : ""}>{item.cpu.toFixed(2)}%</span>
                      </div>
                      <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            item.cpu > 80 ? "bg-cyber-alert-red" :
                            item.cpu > 50 ? "bg-cyber-alert-amber" :
                            "bg-cyber-chart-purple"
                          )}
                          style={{ width: `${Math.min(item.cpu, 100)}%` }}
                        ></div>
                      </div>
                    </div>
                    
                    <div>
                      <div className="mb-1 flex justify-between">
                        <span className="text-muted-foreground">Memory Usage:</span>
                        <span className={item.memory > 5 ? "text-cyber-alert-amber" : ""}>{item.memory.toFixed(2)}%</span>
                      </div>
                      <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            item.memory > 5 ? "bg-cyber-alert-red" :
                            item.memory > 2 ? "bg-cyber-alert-amber" :
                            "bg-cyber-chart-purple"
                          )}
                          style={{ width: `${Math.min(item.memory * 10, 100)}%` }}
                        ></div>
                      </div>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Threads:</span>
                      <span>Unknown</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Handles:</span>
                      <span>Unknown</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Start Time:</span>
                      <span>Unknown</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Command Line:</span>
                      <span className="truncate max-w-[150px]">Unknown</span>
                    </div>
                  </>
                )}

                {isConnection(item) && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Local Address:</span>
                      <span className="font-mono">{item.localAddress}</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Remote Address:</span>
                      <span className="font-mono">{item.remoteAddress}</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <span>{item.status}</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Process:</span>
                      <span>{item.process}</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Established:</span>
                      <span>Unknown</span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Traffic:</span>
                      <span>Unknown</span>
                    </div>
                    
                    <div className="flex justify-between col-span-2">
                      <span className="text-muted-foreground">Location:</span>
                      <span>{item.isInternal ? "Internal Network" : "External Network"}</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Additional Information */}
          <div className="space-y-3">
            <h3 className="text-sm font-medium flex items-center gap-2">
              {isProcess(item) ? (
                <>
                  <FileTerminal className="h-4 w-4 text-muted-foreground" />
                  Process Details
                </>
              ) : (
                <>
                  <Database className="h-4 w-4 text-muted-foreground" />
                  Additional Information
                </>
              )}
            </h3>
            <div className="rounded-md bg-card p-4 border border-border/50 space-y-2">
              {isProcess(item) && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Process ID:</span>
                      <span className="font-mono">{item.pid}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">User:</span>
                      <span>{item.user}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <span>{item.status || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Path:</span>
                      <span className="truncate max-w-[150px]">Unknown</span>
                    </div>
                  </div>
                </>
              )}

              {isConnection(item) && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Country:</span>
                      <span>Unknown</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Reputation:</span>
                      <span>{item.suspicious ? "Suspicious" : "Good"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">ASN:</span>
                      <span>Unknown</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Domain:</span>
                      <span>Unknown</span>
                    </div>
                  </div>
                </>
              )}
              
              <Separator className="my-2" />
              
              <div className="pt-2">
                <p className="text-xs text-muted-foreground">
                  {isProcess(item) 
                    ? "This process was last scanned at 11:45:23 AM. Actions can be performed from the process monitor table."
                    : "This connection was last analyzed at 11:45:23 AM. Traffic monitoring available in real-time view."}
                </p>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
