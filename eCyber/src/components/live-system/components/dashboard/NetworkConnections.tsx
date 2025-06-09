import { useState } from "react";
import { AlertTriangle, Check, Flag, MapPin, Search, Shield, FileTerminal, Network } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem
} from "@/components/ui/dropdown-menu";
import { NetworkConnection } from "../../lib/socket";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { InspectionModal } from "./InspectionModal";

interface NetworkConnectionsProps {
  connections: NetworkConnection[];
}

type ConnectionFilter = "all" | "internal" | "external" | "suspicious";

export function NetworkConnections({ connections }: NetworkConnectionsProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filter, setFilter] = useState<ConnectionFilter>("all");
  const [sortField, setSortField] = useState<keyof NetworkConnection>("remoteAddress");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");
  const [selectedConnection, setSelectedConnection] = useState<NetworkConnection | null>(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);
  const [blockDialogOpen, setBlockDialogOpen] = useState(false);
  const [blockingAddress, setBlockingAddress] = useState("");

  // Filter and sort connections
  const filteredConnections = connections
    .filter(conn => {
      const matchesSearch = 
        conn.localAddress.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.remoteAddress.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.process.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.status.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.pid.toString().includes(searchTerm);
        
      if (filter === "all") return matchesSearch;
      if (filter === "internal") return matchesSearch && conn.isInternal;
      if (filter === "external") return matchesSearch && !conn.isInternal;
      if (filter === "suspicious") return matchesSearch && conn.suspicious;
      
      return matchesSearch;
    })
    .sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return sortDirection === "asc" ? aValue - bValue : bValue - aValue;
      }
      
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        return sortDirection === "asc" 
          ? aValue.localeCompare(bValue) 
          : bValue.localeCompare(aValue);
      }
      
      if (typeof aValue === 'boolean' && typeof bValue === 'boolean') {
        return sortDirection === "asc" 
          ? (aValue ? 1 : 0) - (bValue ? 1 : 0)
          : (bValue ? 1 : 0) - (aValue ? 1 : 0);
      }
      
      return 0;
    });

  const handleSort = (field: keyof NetworkConnection) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const getSortIcon = (field: keyof NetworkConnection) => {
    if (sortField !== field) return null;
    return sortDirection === "asc" ? "↑" : "↓";
  };

  const handleBlockIP = (remoteAddress: string) => {
    setBlockingAddress(remoteAddress);
    setBlockDialogOpen(true);
  };

  const confirmBlock = () => {
    toast.success(`Blocked connection to ${blockingAddress}.`, {
      description: "Firewall rule added successfully."
    });
    setBlockDialogOpen(false);
  };

  const handleTraceRoute = (remoteAddress: string) => {
    toast.info(`Tracing route to ${remoteAddress}...`, {
      description: "Trace results will appear shortly"
    });
    
    // Simulate trace results
    setTimeout(() => {
      toast.success("Trace route completed", {
        description: `Route to ${remoteAddress} determined in 8 hops`
      });
    }, 2500);
  };
  
  const handleInspectConnection = (conn: NetworkConnection) => {
    setSelectedConnection(conn);
    setInspectModalOpen(true);
    toast.info(`Inspecting connection ${conn.localAddress} → ${conn.remoteAddress}`);
  };

  const handleMonitor = (conn: NetworkConnection) => {
    toast.info(`Monitoring traffic for connection ${conn.localAddress} → ${conn.remoteAddress}`, {
      description: "Traffic analysis started"
    });
  };

  const handleKillConnection = (conn: NetworkConnection) => {
    toast.success(`Connection ${conn.localAddress} → ${conn.remoteAddress} terminated`, {
      description: `Process ${conn.process} (PID: ${conn.pid}) connection closed`
    });
    setSelectedConnection(null);
    setInspectModalOpen(false);
  };

  const getFilterCount = (filterType: ConnectionFilter): number => {
    switch (filterType) {
      case "internal": 
        return connections.filter(c => c.isInternal).length;
      case "external": 
        return connections.filter(c => !c.isInternal).length;
      case "suspicious": 
        return connections.filter(c => c.suspicious).length;
      default:
        return connections.length;
    }
  };

  return (
    <>
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
            <div className="flex items-center gap-2">
              <Network className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Network Connections</CardTitle>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="h-7"
                  >
                    {filter === "all" && "All"}
                    {filter === "internal" && "Internal"}
                    {filter === "external" && "External"}
                    {filter === "suspicious" && "Suspicious"}
                    <span className="ml-1">
                      ({getFilterCount(filter)})
                    </span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onClick={() => setFilter("all")}>
                    All ({connections.length})
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setFilter("internal")}>
                    Internal ({getFilterCount("internal")})
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setFilter("external")}>
                    External ({getFilterCount("external")})
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setFilter("suspicious")}>
                    Suspicious ({getFilterCount("suspicious")})
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search connections..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 bg-muted/50"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead
                    onClick={() => handleSort("localAddress")}
                    className="cursor-pointer hover:bg-secondary/50"
                  >
                    Local Address {getSortIcon("localAddress")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("remoteAddress")}
                    className="cursor-pointer hover:bg-secondary/50"
                  >
                    Remote Address {getSortIcon("remoteAddress")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("status")}
                    className="cursor-pointer hover:bg-secondary/50 w-[120px]"
                  >
                    Status {getSortIcon("status")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("pid")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px]"
                  >
                    PID {getSortIcon("pid")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("process")}
                    className="cursor-pointer hover:bg-secondary/50"
                  >
                    Process {getSortIcon("process")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("suspicious")}
                    className="cursor-pointer hover:bg-secondary/50 w-[100px] text-center"
                  >
                    Suspicious {getSortIcon("suspicious")}
                  </TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredConnections.map((conn, index) => (
                  <TableRow
                    key={`${conn.localAddress}-${conn.remoteAddress}-${index}`}
                    className={cn(
                      conn.suspicious ? "bg-destructive/10" : ""
                    )}
                  >
                    <TableCell className="font-mono text-xs">
                      {conn.localAddress}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <div className="flex items-center gap-1.5">
                        {conn.isInternal ? (
                          <MapPin className="h-4 w-4 text-cyber-alert-blue" />
                        ) : (
                          <Flag className="h-4 w-4 text-cyber-alert-amber" />
                        )}
                        {conn.remoteAddress}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className={cn(
                        "px-2 py-0.5 text-xs rounded-full",
                        conn.status === "ESTABLISHED" ? "bg-cyber-alert-green/20 text-cyber-alert-green" :
                        conn.status === "LISTENING" ? "bg-cyber-alert-blue/20 text-cyber-alert-blue" :
                        "bg-muted/20 text-muted-foreground"
                      )}>
                        {conn.status}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{conn.pid}</TableCell>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <FileTerminal className="h-4 w-4 text-muted-foreground" />
                        {conn.process}
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      {conn.suspicious ? (
                        <AlertTriangle className="h-4 w-4 inline-block text-cyber-alert-red" />
                      ) : (
                        <Check className="h-4 w-4 inline-block text-cyber-alert-green" />
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button 
                          variant="destructive" 
                          size="sm"
                          onClick={() => handleBlockIP(conn.remoteAddress)}
                          className="h-7 px-2 text-xs"
                        >
                          Block
                        </Button>
                        <Button 
                          variant="outline"
                          size="sm"
                          onClick={() => handleInspectConnection(conn)}
                          className="h-7 px-2 text-xs"
                        >
                          Inspect
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {filteredConnections.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-6">
                      No connections found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    
      {/* IP Blocking Dialog */}
      <Dialog open={blockDialogOpen} onOpenChange={setBlockDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm IP Blocking</DialogTitle>
            <DialogDescription>
              Are you sure you want to block all connections to and from <span className="font-mono">{blockingAddress}</span>?
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="rounded-md bg-secondary p-3 text-sm">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-5 w-5 text-cyber-alert-amber" />
                <span className="font-medium">Firewall Rule Details</span>
              </div>
              <p className="text-xs text-muted-foreground mb-2">
                This will add a firewall rule to block all traffic from the IP address:
              </p>
              <ul className="text-xs space-y-1">
                <li><span className="text-muted-foreground">Address:</span> {blockingAddress}</li>
                <li><span className="text-muted-foreground">Direction:</span> Inbound & Outbound</li>
                <li><span className="text-muted-foreground">Action:</span> Block</li>
                <li><span className="text-muted-foreground">Protocol:</span> All</li>
                <li><span className="text-muted-foreground">Priority:</span> High</li>
              </ul>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBlockDialogOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmBlock}>
              Block IP
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Inspection Modal */}
      <InspectionModal
        isOpen={inspectModalOpen}
        onClose={() => {
          setInspectModalOpen(false);
          setSelectedConnection(null);
        }}
        item={selectedConnection}
        type="connection"
      />
    </>
  );
}
