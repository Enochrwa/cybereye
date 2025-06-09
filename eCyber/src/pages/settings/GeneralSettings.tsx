
import React from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Settings, Database, Cloud, Shield, Bell, Save } from "lucide-react";
import Header from "../../components/layout/Header";
import { useToast } from "@/hooks/use-toast";

export const GeneralSettings = () => {
  const { toast } = useToast();
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    toast({
      title: "Settings saved",
      description: "Your settings have been successfully updated."
    });
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header />
      
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">General Settings</h1>
              <p className="text-muted-foreground">Configure system-wide settings and preferences</p>
            </div>
            
            <Button onClick={handleSubmit}>
              <Save className="mr-2 h-4 w-4" />
              Save Changes
            </Button>
          </div>
          
          <form onSubmit={handleSubmit}>
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <div className="flex items-center space-x-2">
                    <Settings className="h-5 w-5 text-primary" />
                    <CardTitle>System Configuration</CardTitle>
                  </div>
                  <CardDescription>Configure core system settings</CardDescription>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="system-name">System Name</Label>
                      <Input id="system-name" placeholder="Security Operations Platform" defaultValue="SecOps Platform v2.3" />
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="environment">Environment</Label>
                      <Select defaultValue="production">
                        <SelectTrigger id="environment">
                          <SelectValue placeholder="Select Environment" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="development">Development</SelectItem>
                          <SelectItem value="staging">Staging</SelectItem>
                          <SelectItem value="production">Production</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="timezone">Timezone</Label>
                      <Select defaultValue="utc">
                        <SelectTrigger id="timezone">
                          <SelectValue placeholder="Select Timezone" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="utc">UTC</SelectItem>
                          <SelectItem value="est">EST (UTC-5)</SelectItem>
                          <SelectItem value="pst">PST (UTC-8)</SelectItem>
                          <SelectItem value="cet">CET (UTC+1)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="date-format">Date Format</Label>
                      <Select defaultValue="iso">
                        <SelectTrigger id="date-format">
                          <SelectValue placeholder="Select Date Format" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="iso">ISO 8601 (YYYY-MM-DD)</SelectItem>
                          <SelectItem value="us">US (MM/DD/YYYY)</SelectItem>
                          <SelectItem value="eu">EU (DD/MM/YYYY)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="debug-mode">Debug Mode</Label>
                        <p className="text-sm text-muted-foreground">Enable verbose logging for troubleshooting</p>
                      </div>
                      <Switch id="debug-mode" />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="maintenance-mode">Maintenance Mode</Label>
                        <p className="text-sm text-muted-foreground">Temporarily disable access for non-admin users</p>
                      </div>
                      <Switch id="maintenance-mode" />
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <div className="flex items-center space-x-2">
                    <Database className="h-5 w-5 text-primary" />
                    <CardTitle>Data Management</CardTitle>
                  </div>
                  <CardDescription>Configure data retention policies</CardDescription>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="log-retention">Log Retention Period (days)</Label>
                      <Input id="log-retention" type="number" min="1" defaultValue="90" />
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="backup-frequency">Backup Frequency</Label>
                      <Select defaultValue="daily">
                        <SelectTrigger id="backup-frequency">
                          <SelectValue placeholder="Select Frequency" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="hourly">Hourly</SelectItem>
                          <SelectItem value="daily">Daily</SelectItem>
                          <SelectItem value="weekly">Weekly</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <div className="flex items-center space-x-2">
                      <Cloud className="h-5 w-5 text-primary" />
                      <CardTitle>Integration Settings</CardTitle>
                    </div>
                    <CardDescription>Configure third-party integrations</CardDescription>
                  </CardHeader>
                  
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="api-key">API Key</Label>
                      <Input id="api-key" type="password" defaultValue="••••••••••••••••" />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="api-enabled">API Access</Label>
                        <p className="text-sm text-muted-foreground">Enable API access for integrations</p>
                      </div>
                      <Switch id="api-enabled" defaultChecked />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <div className="flex items-center space-x-2">
                      <Bell className="h-5 w-5 text-primary" />
                      <CardTitle>Alert Settings</CardTitle>
                    </div>
                    <CardDescription>Configure global alert behavior</CardDescription>
                  </CardHeader>
                  
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="alert-threshold">Default Alert Threshold</Label>
                      <Select defaultValue="medium">
                        <SelectTrigger id="alert-threshold">
                          <SelectValue placeholder="Select Threshold" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="auto-suppress">Auto-Suppress Similar Alerts</Label>
                        <p className="text-sm text-muted-foreground">Reduce noise by grouping similar alerts</p>
                      </div>
                      <Switch id="auto-suppress" defaultChecked />
                    </div>
                  </CardContent>
                </Card>
              </div>
              
              <Card>
                <CardHeader>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-primary" />
                    <CardTitle>Security Settings</CardTitle>
                  </div>
                  <CardDescription>Configure security-related settings</CardDescription>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                    <Input id="session-timeout" type="number" min="1" defaultValue="30" />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <Label htmlFor="2fa">Two-Factor Authentication</Label>
                      <p className="text-sm text-muted-foreground">Require 2FA for all users</p>
                    </div>
                    <Switch id="2fa" defaultChecked />
                  </div>
                </CardContent>
              </Card>
              
              <CardFooter className="flex justify-end pb-6">
                <Button type="submit" size="lg">
                  <Save className="mr-2 h-4 w-4" />
                  Save Changes
                </Button>
              </CardFooter>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default GeneralSettings;
