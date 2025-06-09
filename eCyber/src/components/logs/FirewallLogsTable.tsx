import React from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Eye, Download } from "lucide-react";
import { FirewallLog } from '@/types';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface FirewallLogsTableProps {
  logs: FirewallLog[];
  onViewDetails: (log: FirewallLog) => void;
}

const FirewallLogsTable: React.FC<FirewallLogsTableProps> = ({ logs, onViewDetails }) => {
  const handleExportCSV = () => {
    exportToCSV(logs, 'firewall-logs');
  };

  const handleExportJSON = () => {
    exportToJSON(logs, 'firewall-logs');
  };

  return (
    <div className="w-full">
      <div className="flex justify-end mb-4 gap-2">
        <Button variant="outline" size="sm" onClick={handleExportCSV}>
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
        <Button variant="outline" size="sm" onClick={handleExportJSON}>
          <Download className="h-4 w-4 mr-2" />
          Export JSON
        </Button>
      </div>
      
      <div className="border rounded-md">
        <Table>
          <TableHeader>
            <TableRow>
          
              <TableHead>Timestamp</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Destination IP</TableHead>
              <TableHead>Protocol</TableHead>
              <TableHead>Rule ID</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  No firewall logs found
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id}>
                
                  <TableCell>{log.timestamp}</TableCell>
                  <TableCell>
                    <Badge 
                      variant={log.action === "ALLOW" ? "outline" : "destructive"}
                      className={log.action === "ALLOW" 
                        ? "bg-green-500/10 text-green-500 hover:bg-green-500/20 hover:text-green-500" 
                        : ""}
                    >
                      {log.action}
                    </Badge>
                  </TableCell>
                  <TableCell>{log.source_ip}</TableCell>
                  <TableCell>{log.destination_ip}</TableCell>
                  <TableCell>{log.protocol}</TableCell>
                  <TableCell>{log.rule_id}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" onClick={() => onViewDetails(log)}>
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
};

export default FirewallLogsTable;
