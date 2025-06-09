import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { FirewallLog, NetworkEventLog, ThreatLog, SystemLog, MonitoringLog, FirewallRule, IDSRule } from '@/types/logs';

interface LogDetailModalProps {
  log: FirewallLog | NetworkEventLog | ThreatLog | SystemLog | MonitoringLog | FirewallRule | IDSRule | null;
  isOpen: boolean;
  onClose: () => void;
}

const LogDetailModal: React.FC<LogDetailModalProps> = ({ log, isOpen, onClose }) => {
  if (!log) return null;

  const formatDate = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const renderLogDetails = () => {
    // Check log type based on properties
    if ('source_ip' in log && 'destination_ip' in log && 'rule_id' in log) {
      // FirewallLog
      return renderFirewallLog(log as FirewallLog);
    } else if ('source_ip' in log && 'destination_ip' in log && 'application' in log) {
      // NetworkEventLog
      return renderNetworkLog(log as NetworkEventLog);
    } else if ('src_ip' in log && 'dest_ip' in log && 'service' in log) {
      // ThreatLog
      return renderThreatLog(log as ThreatLog);
    } else if ('component' in log && 'level' in log && 'stack_trace' in log) {
      // SystemLog
      return renderSystemLog(log as SystemLog);
    } else if ('type' in log && 'level' in log && 'source' in log) {
      // MonitoringLog
      return renderMonitoringLog(log as MonitoringLog);
    } else if ('direction' in log && 'is_active' in log) {
      // FirewallRule
      return renderFirewallRule(log as FirewallRule);
    } else if ('severity' in log && 'pattern' in log && 'window' in log) {
      // IDSRule
      return renderIDSRule(log as IDSRule);
    } else {
      return <p>Unknown log type</p>;
    }
  };

  const renderFirewallLog = (log: FirewallLog) => (
    <>
      <DialogHeader>
        <DialogTitle>Firewall Log Details</DialogTitle>
        <DialogDescription>
          ID: {log.id} • {formatDate(log.timestamp)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Action</h3>
          <Badge 
            variant={log.action === "ALLOW" ? "outline" : "destructive"}
            className={log.action === "ALLOW" ? "bg-green-500/10 text-green-500" : ""}
          >
            {log.action}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Protocol</h3>
          <p>{log.protocol}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source IP</h3>
          <p>{log.source_ip}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Destination IP</h3>
          <p>{log.destination_ip}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Rule ID</h3>
          <p>{log.rule_id}</p>
        </div>
      </div>
    </>
  );

  const renderNetworkLog = (log: NetworkEventLog) => (
    <>
      <DialogHeader>
        <DialogTitle>Network Event Details</DialogTitle>
        <DialogDescription>
          ID: {log.id} • {formatDate(log.timestamp)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Event Type</h3>
          <Badge variant="outline" className="bg-blue-500/10 text-blue-500">
            {log.event_type}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Protocol</h3>
          <p>{log.protocol}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source</h3>
          <p>IP: {log.source_ip}</p>
          <p>MAC: {log.source_mac}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Destination</h3>
          <p>IP: {log.destination_ip}</p>
          <p>Port: {log.destination_port}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Application</h3>
          <p>{log.application}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Packet Length</h3>
          <p>{log.length} bytes</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Payload</h3>
          <ScrollArea className="h-20 rounded-md border p-2">
            {log.payload}
          </ScrollArea>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Geographic Location</h3>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <p className="text-xs text-muted-foreground">Country</p>
              <p>{log.geo.country}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">City</p>
              <p>{log.geo.city}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">ISP</p>
              <p>{log.geo.isp}</p>
            </div>
          </div>
        </div>
      </div>
    </>
  );

  const renderThreatLog = (log: ThreatLog) => (
    <>
      <DialogHeader>
        <DialogTitle>Threat Detection Details</DialogTitle>
        <DialogDescription>
          ID: {log.id} • {formatDate(log.timestamp)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Event Type</h3>
          <Badge variant="destructive">
            {log.event_type}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Protocol</h3>
          <p>{log.protocol}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source</h3>
          <p>IP: {log.src_ip}</p>
          <p>MAC: {log.src_mac}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Destination</h3>
          <p>IP: {log.dest_ip}</p>
          <p>Port: {log.port}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Service</h3>
          <p>{log.service}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Packet Size</h3>
          <p>{log.packet_size} bytes</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Message</h3>
          <ScrollArea className="h-20 rounded-md border p-2">
            {log.message}
          </ScrollArea>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Geographic Location</h3>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <p className="text-xs text-muted-foreground">Country</p>
              <p>{log.geo.country}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">City</p>
              <p>{log.geo.city}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">ISP</p>
              <p>{log.geo.isp}</p>
            </div>
          </div>
        </div>
      </div>
    </>
  );

  const renderSystemLog = (log: SystemLog) => (
    <>
      <DialogHeader>
        <DialogTitle>System Log Details</DialogTitle>
        <DialogDescription>
          ID: {log.id} • {formatDate(log.timestamp)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Level</h3>
          <Badge 
            variant={log.level.toLowerCase() === 'error' ? 'destructive' : 'outline'}
            className={log.level.toLowerCase() !== 'error' ? 'bg-blue-500/10 text-blue-500' : ''}
          >
            {log.level.toUpperCase()}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Component</h3>
          <p>{log.component}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">User ID</h3>
          <p>{log.user_id || 'N/A'}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source IP</h3>
          <p>{log.source_ip || 'N/A'}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Request ID</h3>
          <p>{log.request_id || 'N/A'}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Duration</h3>
          <p>{log.duration_ms !== undefined ? `${log.duration_ms} ms` : 'N/A'}</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Message</h3>
          <p>{log.message}</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Details</h3>
          <ScrollArea className="h-20 rounded-md border p-2">
            <pre className="text-xs">{JSON.stringify(log.details, null, 2)}</pre>
          </ScrollArea>
        </div>
        {log.stack_trace && (
          <div className="space-y-2 md:col-span-2">
            <h3 className="text-sm font-semibold">Stack Trace</h3>
            <ScrollArea className="h-40 rounded-md border p-2 bg-gray-50 dark:bg-gray-900">
              <pre className="text-xs whitespace-pre-wrap font-mono">{log.stack_trace}</pre>
            </ScrollArea>
          </div>
        )}
        {log.resolved !== undefined && (
          <div className="space-y-2 md:col-span-2">
            <h3 className="text-sm font-semibold">Resolution Status</h3>
            <div className="flex items-center space-x-2">
              <Badge 
                variant="outline" 
                className={log.resolved ? 
                  "bg-green-500/10 text-green-500" : 
                  "bg-amber-500/10 text-amber-500"
                }
              >
                {log.resolved ? 'Resolved' : 'Unresolved'}
              </Badge>
              {log.resolution_notes && <p className="text-sm">{log.resolution_notes}</p>}
            </div>
          </div>
        )}
      </div>
    </>
  );

  const renderMonitoringLog = (log: MonitoringLog) => (
    <>
      <DialogHeader>
        <DialogTitle>Monitoring Log Details</DialogTitle>
        <DialogDescription>
          ID: {log.id} • {formatDate(log.timestamp)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Level</h3>
          <Badge 
            variant={log.level === 'ERROR' ? 'destructive' : 'outline'}
            className={
              log.level === 'WARNING' 
                ? 'bg-amber-500/10 text-amber-500' 
                : log.level === 'INFO' 
                  ? 'bg-blue-500/10 text-blue-500' 
                  : ''
            }
          >
            {log.level}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Type</h3>
          <p>{log.type}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source</h3>
          <p>{log.source}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Action</h3>
          <p>{log.action}</p>
        </div>
        {log.user && (
          <div className="space-y-2 md:col-span-2">
            <h3 className="text-sm font-semibold">User</h3>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <p className="text-xs text-muted-foreground">ID</p>
                <p>{log.user.id}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Username</p>
                <p>{log.user.username}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Email</p>
                <p>{log.user.email}</p>
              </div>
            </div>
          </div>
        )}
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Message</h3>
          <p>{log.message}</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Details</h3>
          <ScrollArea className="h-40 rounded-md border p-2">
            <pre className="text-xs">{JSON.stringify(log.details, null, 2)}</pre>
          </ScrollArea>
        </div>
      </div>
    </>
  );

  const renderFirewallRule = (rule: FirewallRule) => (
    <>
      <DialogHeader>
        <DialogTitle>Firewall Rule Details</DialogTitle>
        <DialogDescription>
          ID: {rule.id} • Created: {formatDate(rule.created_at)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Name</h3>
          <p>{rule.name}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Status</h3>
          <Badge 
            variant="outline" 
            className={rule.is_active ? 
              "bg-green-500/10 text-green-500" : 
              "bg-gray-500/10 text-gray-500"
            }
          >
            {rule.is_active ? 'Active' : 'Inactive'}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Action</h3>
          <Badge 
            variant={rule.action === "ALLOW" ? "outline" : "destructive"}
            className={rule.action === "ALLOW" ? "bg-green-500/10 text-green-500" : ""}
          >
            {rule.action}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Direction</h3>
          <p>{rule.direction}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Protocol</h3>
          <p>{rule.protocol}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source</h3>
          <p className="text-sm">IP: {rule.source_ip}</p>
          {rule.source_port && <p className="text-sm">Port: {rule.source_port}</p>}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Destination</h3>
          <p className="text-sm">IP: {rule.destination_ip}</p>
          {rule.destination_port && <p className="text-sm">Port: {rule.destination_port}</p>}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Last Updated</h3>
          <p>{formatDate(rule.updated_at)}</p>
        </div>
      </div>
    </>
  );

  const renderIDSRule = (rule: IDSRule) => (
    <>
      <DialogHeader>
        <DialogTitle>IDS Rule Details</DialogTitle>
        <DialogDescription>
          ID: {rule.id} • Created: {formatDate(rule.created_at)}
        </DialogDescription>
      </DialogHeader>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Name</h3>
          <p>{rule.name}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Status</h3>
          <Badge 
            variant="outline" 
            className={rule.active ? 
              "bg-green-500/10 text-green-500" : 
              "bg-gray-500/10 text-gray-500"
            }
          >
            {rule.active ? 'Active' : 'Inactive'}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Action</h3>
          <Badge 
            variant={rule.action === "BLOCK" ? "destructive" : "outline"}
            className={rule.action !== "BLOCK" ? "bg-blue-500/10 text-blue-500" : ""}
          >
            {rule.action}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Severity</h3>
          <Badge 
            variant={rule.severity === "high" ? "destructive" : "outline"}
            className={
              rule.severity === "medium" 
                ? "bg-amber-500/10 text-amber-500" 
                : rule.severity === "low" 
                  ? "bg-blue-500/10 text-blue-500" 
                  : ""
            }
          >
            {rule.severity}
          </Badge>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Protocol</h3>
          <p>{rule.protocol}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Threshold</h3>
          <p>{rule.threshold} events in {rule.window} seconds</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Source</h3>
          <p className="text-sm">IP: {rule.source_ip}</p>
          <p className="text-sm">Port: {rule.source_port}</p>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Destination</h3>
          <p className="text-sm">IP: {rule.destination_ip}</p>
          <p className="text-sm">Port: {rule.destination_port}</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Description</h3>
          <p>{rule.description}</p>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Pattern</h3>
          <ScrollArea className="h-20 rounded-md border p-2">
            <pre className="text-xs font-mono">{rule.pattern}</pre>
          </ScrollArea>
        </div>
        <div className="space-y-2 md:col-span-2">
          <h3 className="text-sm font-semibold">Content Modifiers</h3>
          <ScrollArea className="h-20 rounded-md border p-2">
            <pre className="text-xs">{JSON.stringify(rule.content_modifiers, null, 2)}</pre>
          </ScrollArea>
        </div>
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Last Updated</h3>
          <p>{formatDate(rule.updated_at)}</p>
        </div>
      </div>
    </>
  );

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <ScrollArea className="flex-1">
          <div className="p-2">
            {renderLogDetails()}
          </div>
        </ScrollArea>
        <DialogFooter className="mt-4">
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default LogDetailModal;
