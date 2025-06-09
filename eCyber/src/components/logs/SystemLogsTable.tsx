import React from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Eye, Download } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SystemLog } from '@/types/logs';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface SystemLogsTableProps {
  logs: SystemLog[];
  onViewDetails: (log: SystemLog) => void;
}

export const SystemLogsTable: React.FC<SystemLogsTableProps> = ({ logs, onViewDetails }) => {
  const handleExportCSV = () => {
    exportToCSV(logs, 'system-logs');
  };

  const handleExportJSON = () => {
    exportToJSON(logs, 'system-logs');
  };

  const getLevelVariant = (level: string) => {
    switch(level.toLowerCase()) {
      case 'error': return 'destructive';
      case 'warning': return 'outline'; // Using outline with custom colors
      case 'info': return 'outline'; // Using outline with custom colors
      default: return 'outline';
    }
  };

  const getLevelClass = (level: string) => {
    switch(level.toLowerCase()) {
      case 'error': return '';
      case 'warning': return 'bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 hover:text-amber-500';
      case 'info': return 'bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 hover:text-blue-500';
      default: return 'bg-gray-500/10 text-gray-500 hover:bg-gray-500/20 hover:text-gray-500';
    }
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
              <TableHead>Level</TableHead>
              <TableHead>Component</TableHead>
              <TableHead>Message</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                  No system logs found
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>{log.timestamp}</TableCell>
                  <TableCell>
                    <Badge 
                      variant={getLevelVariant(log.level)}
                      className={getLevelClass(log.level)}
                    >
                      {log.level.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>{log.component}</TableCell>
                  <TableCell>
                    <div className="max-w-[250px] truncate" title={log.message}>
                      {log.message}
                    </div>
                  </TableCell>
                  <TableCell>{log.user_id ? `User ${log.user_id}` : 'System'}</TableCell>
                  <TableCell>{log.source_ip || 'N/A'}</TableCell>
                  <TableCell>
                    {log.resolved !== undefined ? (
                      <Badge variant={log.resolved ? "outline" : "outline"} 
                        className={log.resolved ? 
                          "bg-green-500/10 text-green-500 hover:bg-green-500/20 hover:text-green-500" : 
                          "bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 hover:text-amber-500"
                        }>
                        {log.resolved ? 'Resolved' : 'Unresolved'}
                      </Badge>
                    ) : 'N/A'}
                  </TableCell>
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

