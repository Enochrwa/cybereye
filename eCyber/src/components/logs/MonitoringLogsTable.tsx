import React from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Eye, Download } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { MonitoringLog } from '@/types/logs';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface MonitoringLogsTableProps {
  logs: MonitoringLog[];
  onViewDetails: (log: MonitoringLog) => void;
}

const MonitoringLogsTable: React.FC<MonitoringLogsTableProps> = ({ logs, onViewDetails }) => {
  const handleExportCSV = () => {
    exportToCSV(logs, 'monitoring-logs');
  };

  const handleExportJSON = () => {
    exportToJSON(logs, 'monitoring-logs');
  };

  const getLevelVariant = (level: string) => {
    switch(level) {
      case 'ERROR': return 'destructive';
      case 'WARNING': return 'outline';
      case 'INFO': return 'outline';
      default: return 'outline';
    }
  };

  const getLevelClass = (level: string) => {
    switch(level) {
      case 'ERROR': return '';
      case 'WARNING': return 'bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 hover:text-amber-500';
      case 'INFO': return 'bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 hover:text-blue-500';
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
              <TableHead>Type</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Message</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>User</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                  No monitoring logs found
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
                      {log.level}
                    </Badge>
                  </TableCell>
                  <TableCell>{log.type}</TableCell>
                  <TableCell>{log.source}</TableCell>
                  <TableCell>
                    <div className="max-w-[250px] truncate" title={log.message}>
                      {log.message}
                    </div>
                  </TableCell>
                  <TableCell>{log.action}</TableCell>
                  <TableCell>
                    {log.user ? (
                      <div className="flex flex-col">
                        <span className="text-xs font-medium">{log.user.username}</span>
                        <span className="text-xs text-muted-foreground">{log.user.email}</span>
                      </div>
                    ) : log.user_id ? `User ${log.user_id}` : 'System'}
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

export default MonitoringLogsTable;