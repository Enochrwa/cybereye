
import React, { useState } from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Eye, Download, Edit, Trash2, CheckSquare, XSquare } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FirewallRule, IDSRule } from '@/types/logs';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface RulesTableProps {
  firewallRules: FirewallRule[];
  idsRules: IDSRule[];
  onEdit: (rule: FirewallRule | IDSRule, type: 'firewall' | 'ids') => void;
  onDelete: (id: number, type: 'firewall' | 'ids') => void;
  onToggle: (id: number, active: boolean, type: 'firewall' | 'ids') => void;
}

const RulesTable: React.FC<RulesTableProps> = ({ 
  firewallRules, 
  idsRules, 
  onEdit, 
  onDelete, 
  onToggle 
}) => {
  const [activeTab, setActiveTab] = useState<'firewall' | 'ids'>('firewall');

  const handleExportCSV = () => {
    if (activeTab === 'firewall') {
      exportToCSV(firewallRules, 'firewall-rules');
    } else {
      exportToCSV(idsRules, 'ids-rules');
    }
  };

  const handleExportJSON = () => {
    if (activeTab === 'firewall') {
      exportToJSON(firewallRules, 'firewall-rules');
    } else {
      exportToJSON(idsRules, 'ids-rules');
    }
  };

  return (
    <div className="w-full">
      <div className="flex justify-between items-center mb-4">
        <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as 'firewall' | 'ids')}>
          <TabsList>
            <TabsTrigger value="firewall">Firewall Rules</TabsTrigger>
            <TabsTrigger value="ids">IDS Rules</TabsTrigger>
          </TabsList>
        </Tabs>
        
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleExportCSV}>
            <Download className="h-4 w-4 mr-2" />
            Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={handleExportJSON}>
            <Download className="h-4 w-4 mr-2" />
            Export JSON
          </Button>
        </div>
      </div>
      
      <div className="border rounded-md">
        <TabsContent value="firewall" className="m-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Direction</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {firewallRules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                    No firewall rules found
                  </TableCell>
                </TableRow>
              ) : (
                firewallRules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell>{rule.name}</TableCell>
                    <TableCell>{rule.direction}</TableCell>
                    <TableCell>{rule.protocol}</TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="text-xs font-medium">{rule.source_ip}</span>
                        {rule.source_port && <span className="text-xs text-muted-foreground">Port: {rule.source_port}</span>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="text-xs font-medium">{rule.destination_ip}</span>
                        {rule.destination_port && <span className="text-xs text-muted-foreground">Port: {rule.destination_port}</span>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={rule.action === "ALLOW" ? "outline" : "destructive"} 
                        className={rule.action === "ALLOW" ? "bg-green-500/10 text-green-500" : ""}
                      >
                        {rule.action}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Switch 
                        checked={rule.is_active} 
                        onCheckedChange={(checked) => onToggle(rule.id, checked, 'firewall')}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" onClick={() => onEdit(rule, 'firewall')}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => onDelete(rule.id, 'firewall')}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TabsContent>
        
        <TabsContent value="ids" className="m-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Pattern</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {idsRules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    No IDS rules found
                  </TableCell>
                </TableRow>
              ) : (
                idsRules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell>{rule.id}</TableCell>
                    <TableCell>{rule.name}</TableCell>
                    <TableCell>
                      <Badge 
                        variant={rule.action === "BLOCK" ? "destructive" : "outline"}
                        className={rule.action !== "BLOCK" ? "bg-blue-500/10 text-blue-500" : ""}
                      >
                        {rule.action}
                      </Badge>
                    </TableCell>
                    <TableCell>{rule.protocol}</TableCell>
                    <TableCell>
                      <div className="max-w-[150px] truncate" title={rule.pattern}>
                        {rule.pattern}
                      </div>
                    </TableCell>
                    <TableCell>
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
                    </TableCell>
                    <TableCell>
                      <Switch 
                        checked={rule.active} 
                        onCheckedChange={(checked) => onToggle(rule.id, checked, 'ids')}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" onClick={() => onEdit(rule, 'ids')}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => onDelete(rule.id, 'ids')}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TabsContent>
      </div>
    </div>
  );
};

export default RulesTable