import { useState } from "react";
import { AlertTriangle, Check, Search, FileTerminal, ShieldCheck, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ProcessItem } from "../../lib/socket";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { 
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { InspectionModal } from "./InspectionModal";

interface ProcessMonitorProps {
  processes: ProcessItem[];
}

export function ProcessMonitor({ processes }: ProcessMonitorProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [sortField, setSortField] = useState<keyof ProcessItem>("cpu");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const [selectedProcess, setSelectedProcess] = useState<ProcessItem | null>(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);

  // Filter and sort processes
  const filteredProcesses = processes.filter(process => {
    const lowerSearchTerm = searchTerm.toLowerCase();
    return (
      process.name.toLowerCase().includes(lowerSearchTerm) ||
      process.user.toLowerCase().includes(lowerSearchTerm) ||
      process.pid.toString().includes(lowerSearchTerm) ||
      (process.status && process.status.toLowerCase().includes(lowerSearchTerm))
    );
  }).sort((a, b) => {
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

  const handleSort = (field: keyof ProcessItem) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("desc"); // Default to descending when changing fields
    }
  };

  const getSortIcon = (field: keyof ProcessItem) => {
    if (sortField !== field) return null;
    return sortDirection === "asc" ? "↑" : "↓";
  };

  const handleKill = (pid: number, name: string) => {
    toast.success(`Process ${name} (PID: ${pid}) terminated.`, {
      description: "Process has been successfully terminated."
    });
    setSelectedProcess(null);
    setInspectModalOpen(false);
  };

  const handleInspect = (process: ProcessItem) => {
    setSelectedProcess(process);
    setInspectModalOpen(true);
    toast.info(`Inspecting process ${process.name} (PID: ${process.pid})...`);
  };

  const handleSuspend = (pid: number, name: string) => {
    toast.info(`Process ${name} (PID: ${pid}) suspended.`);
  };

  const handleAnalyze = (pid: number, name: string) => {
    toast.info(`Analyzing process ${name} (PID: ${pid}) for suspicious activity...`, {
      description: "Security scan initiated",
      duration: 3000
    });
  };

  return (
    <>
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
            <div className="flex items-center gap-2">
              <CardTitle>Process Monitor</CardTitle>
              <span className="bg-secondary/50 text-xs px-2 py-0.5 rounded">
                {processes.length} Total
              </span>
            </div>
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search processes..."
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
                    onClick={() => handleSort("pid")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px]"
                  >
                    PID {getSortIcon("pid")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("name")}
                    className="cursor-pointer hover:bg-secondary/50"
                  >
                    Name {getSortIcon("name")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("user")}
                    className="cursor-pointer hover:bg-secondary/50"
                  >
                    User {getSortIcon("user")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("status")}
                    className="cursor-pointer hover:bg-secondary/50 w-[100px]"
                  >
                    Status {getSortIcon("status")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("cpu")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px] text-right"
                  >
                    CPU % {getSortIcon("cpu")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("memory")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px] text-right"
                  >
                    MEM % {getSortIcon("memory")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("signed")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px] text-center"
                  >
                    Signed {getSortIcon("signed")}
                  </TableHead>
                  <TableHead
                    onClick={() => handleSort("suspicious")}
                    className="cursor-pointer hover:bg-secondary/50 w-[80px] text-center"
                  >
                    Risk {getSortIcon("suspicious")}
                  </TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredProcesses.map((process) => (
                  <TableRow
                    key={process.pid}
                    className={cn(
                      process.suspicious ? "bg-destructive/10" : "",
                      process.cpu > 70 ? "bg-cyber-alert-amber/10" : ""
                    )}
                  >
                    <TableCell className="font-mono text-xs">{process.pid}</TableCell>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <FileTerminal className="h-4 w-4 text-muted-foreground" />
                        {process.name}
                      </div>
                    </TableCell>
                    <TableCell>{process.user}</TableCell>
                    <TableCell>
                      {process.status && (
                        <span className={cn(
                          "inline-block px-2 py-0.5 text-xs rounded-full",
                          process.status === "running" ? "bg-cyber-alert-green/20 text-cyber-alert-green" :
                          process.status === "sleeping" ? "bg-cyber-alert-blue/20 text-cyber-alert-blue" :
                          "bg-muted/20 text-muted-foreground"
                        )}>
                          {process.status}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className={cn(
                      "text-right",
                      process.cpu > 80 ? "text-cyber-alert-red font-medium" : 
                      process.cpu > 50 ? "text-cyber-alert-amber" : ""
                    )}>
                      {process.cpu.toFixed(1)}
                    </TableCell>
                    <TableCell className={cn(
                      "text-right",
                      process.memory > 5 ? "text-cyber-alert-red font-medium" : 
                      process.memory > 2 ? "text-cyber-alert-amber" : ""
                    )}>
                      {process.memory.toFixed(2)}
                    </TableCell>
                    <TableCell className="text-center">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div>
                              {process.signed === null ? (
                                <span className="text-xs text-muted-foreground">N/A</span>
                              ) : process.signed ? (
                                <ShieldCheck className="h-4 w-4 inline-block text-cyber-alert-green" />
                              ) : (
                                <AlertTriangle className="h-4 w-4 inline-block text-cyber-alert-amber" />
                              )}
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            {process.signed === null ? "Signature information not available" : 
                             process.signed ? "Digitally signed" : "Not signed or invalid signature"}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </TableCell>
                    <TableCell className="text-center">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger>
                            {process.suspicious ? (
                              <AlertTriangle className="h-4 w-4 inline-block text-cyber-alert-red" />
                            ) : (
                              <Check className="h-4 w-4 inline-block text-cyber-alert-green" />
                            )}
                          </TooltipTrigger>
                          <TooltipContent>
                            {process.suspicious ? "Suspicious behavior detected" : "No suspicious activity detected"}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button 
                          variant="destructive" 
                          size="sm"
                          onClick={() => handleKill(process.pid, process.name)}
                          className="h-7 px-2 text-xs"
                        >
                          Kill
                        </Button>
                        <Button 
                          variant="outline"
                          size="sm"
                          onClick={() => handleInspect(process)}
                          className="h-7 px-2 text-xs"
                        >
                          Inspect
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {filteredProcesses.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground py-6">
                      No processes found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Inspection Modal */}
      <InspectionModal
        isOpen={inspectModalOpen}
        onClose={() => {
          setInspectModalOpen(false);
          setSelectedProcess(null);
        }}
        item={selectedProcess}
        type="process"
      />
    </>
  );
}
