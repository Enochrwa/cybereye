import React, { useState, useEffect } from 'react'; // Import useState, useEffect
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
// Other imports like Shield, Lock, RefreshCw are already there
import { Settings as SettingsIcon, Bell, Database, Shield, Lock, RefreshCw } from 'lucide-react';
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
// Label is already imported
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Header from '../components/layout/Header';
import ThemeSwitcher from '../components/settings/ThemeSwitcher';
import SystemUpdater from '../components/settings/SystemUpdater';
import { useToast } from "@/hooks/use-toast";
import { TwoFactorAuthSetupDialog } from '../components/settings/TwoFactorAuthSetupDialog';
import { ChangePasswordDialog } from '../components/settings/ChangePasswordDialog'; // Import new dialog
import { useAuth } from '@/context/AuthContext';
import { disable2FA } from '@/services/api';


const Settings = () => {
  const { toast } = useToast();
  const { user, fetchUserProfile, updateUser2FAStatus, isLoading: isAuthLoading } = useAuth();
  const [isTwoFactorAuthDialogOpen, setIsTwoFactorAuthDialogOpen] = useState(false);
  // Remove local isTwoFactorEnabled, use user.is_two_factor_enabled from context
  const [isUpdating2FA, setIsUpdating2FA] = useState(false);
  const [isChangePasswordDialogOpen, setIsChangePasswordDialogOpen] = useState(false);

  // useEffect to fetch initial 2FA status is no longer needed here if AuthProvider handles initial user load.
  // The `user` object from `useAuth()` will have the latest `is_two_factor_enabled`.

  const handleTwoFactorSwitchChange = async (checked: boolean) => {
    if (checked) {
      // User wants to enable 2FA
      setIsTwoFactorAuthDialogOpen(true);
    } else {
      // User wants to disable 2FA
      setIsUpdating2FA(true);
      try {
        await disable2FA(); // Actual API call
        toast({ title: "Success", description: "2FA disabled successfully." });
        updateUser2FAStatus(false); // Update context state
        await fetchUserProfile(); // Refresh user profile
      } catch (error: any) {
        const detail = error.response?.data?.detail || error.message || "Could not disable 2FA.";
        toast({ title: "Error", description: detail, variant: "destructive" });
      } finally {
        setIsUpdating2FA(false);
      }
    }
  };

  const handle2FASuccess = async () => { // Modified to be async
    // No need to call updateUser2FAStatus here, dialog does it.
    // fetchUserProfile is also called by dialog.
    // Just ensure UI consistency if needed, though context should drive it.
    // If further actions were needed on this page after dialog success, they'd go here.
  };
  
  const handleSaveChanges = () => {
    toast({
      title: "Settings Saved",
      description: "Your settings have been updated successfully",
    });
  };
  
  return (
    <div className="flex h-screen bg-background">
      
      <div className="flex-1 flex flex-col overflow-hidden">
       
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto">
            {/* Page header */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight">System Settings</h1>
                <p className="text-muted-foreground">Configure system settings and integrations</p>
              </div>
              
              <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
                Last updated: {new Date().toLocaleTimeString()}
              </div>
            </div>
            
            {/* Settings tabs */}
            <Tabs defaultValue="security"> {/* Default to security tab for easier testing */}
              <TabsList className="mb-6">
                <TabsTrigger value="general">General</TabsTrigger>
                <TabsTrigger value="notifications">Notifications</TabsTrigger>
                <TabsTrigger value="security">Security</TabsTrigger>
                <TabsTrigger value="data">Data Management</TabsTrigger>
                <TabsTrigger value="integrations">Integrations</TabsTrigger>
              </TabsList>
              
              {/* General Settings */}
              <TabsContent value="general">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center">
                        <SettingsIcon className="mr-2" size={18} />
                        General Settings
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      <div className="space-y-2">
                        <Label htmlFor="system-name">System Name</Label>
                        <Input id="system-name" defaultValue="eCyber Security Platform" />
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="timezone">Timezone</Label>
                        <Input id="timezone" defaultValue="UTC (Coordinated Universal Time)" />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium">Analytics</h4>
                          <p className="text-sm text-muted-foreground">Allow anonymous usage data collection</p>
                        </div>
                        <Switch defaultChecked />
                      </div>
                    </CardContent>
                    <CardFooter>
                      <Button className="ml-auto" onClick={handleSaveChanges}>Save Changes</Button>
                    </CardFooter>
                  </Card>
                  
                  <div className="space-y-6">
                    <ThemeSwitcher />
                    <SystemUpdater />
                  </div>
                </div>
              </TabsContent>
              
              {/* Notification Settings */}
              <TabsContent value="notifications">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Bell className="mr-2" size={18} />
                      Notification Settings
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Email Notifications</h4>
                        <p className="text-sm text-muted-foreground">Receive critical alerts via email</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">SMS Notifications</h4>
                        <p className="text-sm text-muted-foreground">Receive urgent alerts via SMS</p>
                      </div>
                      <Switch />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Dashboard Alerts</h4>
                        <p className="text-sm text-muted-foreground">Show alerts on the dashboard</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Email Recipients</Label>
                      <Input defaultValue="admin@example.com, security@example.com" />
                      <p className="text-xs text-muted-foreground">Separate multiple emails with commas</p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Alert Threshold</Label>
                      <div className="grid grid-cols-3 gap-4">
                        <div className="flex items-center justify-between p-3 border border-border rounded-md">
                          <div>Critical</div>
                          <Switch defaultChecked />
                        </div>
                        <div className="flex items-center justify-between p-3 border border-border rounded-md">
                          <div>Warning</div>
                          <Switch defaultChecked />
                        </div>
                        <div className="flex items-center justify-between p-3 border border-border rounded-md">
                          <div>Info</div>
                          <Switch />
                        </div>
                      </div>
                    </div>
                  </CardContent>
                  <CardFooter>
                    <Button className="ml-auto" onClick={handleSaveChanges}>Save Changes</Button>
                  </CardFooter>
                </Card>
              </TabsContent>
              
              {/* Security Settings */}
              <TabsContent value="security">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Shield className="mr-2" size={18} />
                      Security Settings
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Two-Factor Authentication</h4>
                        <p className="text-sm text-muted-foreground">
                          {user?.is_two_factor_enabled 
                            ? "2FA is currently enabled for your account." 
                            : "Add an extra layer of security to your account."}
                        </p>
                      </div>
                      <Switch 
                        checked={user?.is_two_factor_enabled || false} 
                        onCheckedChange={handleTwoFactorSwitchChange}
                        disabled={isUpdating2FA || isAuthLoading}
                      />
                    </div>

                    {/* Change Password Button */}
                    <div className="pt-2">
                       <Button variant="outline" onClick={() => setIsChangePasswordDialogOpen(true)}>
                         <Lock className="mr-2 h-4 w-4" />
                         Change Password
                       </Button>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Session Timeout</h4>
                        <p className="text-sm text-muted-foreground">Automatically log out inactive users</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Session Timeout Duration</Label>
                      <Input defaultValue="30" type="number" className="max-w-xs" />
                      <p className="text-xs text-muted-foreground">Minutes of inactivity before session expires</p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Password Policy</Label>
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <Switch id="pw-length" defaultChecked className="mr-2" />
                          <Label htmlFor="pw-length">Minimum 12 characters</Label>
                        </div>
                        <div className="flex items-center">
                          <Switch id="pw-upper" defaultChecked className="mr-2" />
                          <Label htmlFor="pw-upper">Require uppercase letters</Label>
                        </div>
                        <div className="flex items-center">
                          <Switch id="pw-special" defaultChecked className="mr-2" />
                          <Label htmlFor="pw-special">Require special characters</Label>
                        </div>
                        <div className="flex items-center">
                          <Switch id="pw-expire" defaultChecked className="mr-2" />
                          <Label htmlFor="pw-expire">Expire passwords after 90 days</Label>
                        </div>
                      </div>
                    </div>
                    
                    <div className="pt-2">
                      <Button variant="outline" className="mr-2">
                        <Lock className="mr-2 h-4 w-4" />
                        Security Audit Log
                      </Button>
                      <Button variant="outline">
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Force Password Reset
                      </Button>
                    </div>
                  </CardContent>
                  <CardFooter>
                    <Button className="ml-auto" onClick={handleSaveChanges}>Save Changes</Button>
                  </CardFooter>
                </Card>
              </TabsContent>
              
              {/* Data Management */}
              <TabsContent value="data">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Database className="mr-2" size={18} />
                      Data Management
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="space-y-2">
                      <Label>Data Retention Period</Label>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <Label htmlFor="logs-retention" className="text-sm">Security Logs</Label>
                          <div className="flex items-center mt-1">
                            <Input id="logs-retention" defaultValue="90" type="number" className="mr-2" />
                            <span className="text-sm">days</span>
                          </div>
                        </div>
                        <div>
                          <Label htmlFor="events-retention" className="text-sm">Event Data</Label>
                          <div className="flex items-center mt-1">
                            <Input id="events-retention" defaultValue="180" type="number" className="mr-2" />
                            <span className="text-sm">days</span>
                          </div>
                        </div>
                        <div>
                          <Label htmlFor="metrics-retention" className="text-sm">Performance Metrics</Label>
                          <div className="flex items-center mt-1">
                            <Input id="metrics-retention" defaultValue="365" type="number" className="mr-2" />
                            <span className="text-sm">days</span>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Automatic Data Cleanup</h4>
                        <p className="text-sm text-muted-foreground">Automatically remove data older than retention period</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Database Backups</h4>
                        <p className="text-sm text-muted-foreground">Schedule regular database backups</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Backup Schedule</Label>
                      <Input defaultValue="Daily at 2:00 AM" />
                    </div>
                    
                    <div className="space-y-2">
                      <Label>Backup Location</Label>
                      <Input defaultValue="/backups/isimbi/" />
                    </div>
                    
                    <div className="pt-2">
                      <Button variant="outline" className="mr-2">
                        <Database className="mr-2 h-4 w-4" />
                        Backup Now
                      </Button>
                      <Button variant="outline">
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Restore from Backup
                      </Button>
                    </div>
                  </CardContent>
                  <CardFooter>
                    <Button className="ml-auto" onClick={handleSaveChanges}>Save Changes</Button>
                  </CardFooter>
                </Card>
              </TabsContent>
              
              {/* Integrations */}
              <TabsContent value="integrations">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <SettingsIcon className="mr-2" size={18} />
                      External Integrations
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-6">
                      <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                        <div className="flex items-center">
                          <div className="w-10 h-10 bg-blue-500/10 rounded-full flex items-center justify-center text-blue-500 mr-4">
                            <Shield className="h-5 w-5" />
                          </div>
                          <div>
                            <h4 className="font-medium">SIEM Integration</h4>
                            <p className="text-sm text-muted-foreground">Connect to enterprise SIEM systems</p>
                          </div>
                        </div>
                        <Switch defaultChecked />
                      </div>
                      
                      <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                        <div className="flex items-center">
                          <div className="w-10 h-10 bg-amber-500/10 rounded-full flex items-center justify-center text-amber-500 mr-4">
                            <Bell className="h-5 w-5" />
                          </div>
                          <div>
                            <h4 className="font-medium">Incident Response Platform</h4>
                            <p className="text-sm text-muted-foreground">Connect to incident management system</p>
                          </div>
                        </div>
                        <Switch />
                      </div>
                      
                      <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                        <div className="flex items-center">
                          <div className="w-10 h-10 bg-green-500/10 rounded-full flex items-center justify-center text-green-500 mr-4">
                            <Database className="h-5 w-5" />
                          </div>
                          <div>
                            <h4 className="font-medium">Threat Intelligence Feeds</h4>
                            <p className="text-sm text-muted-foreground">Integrate external threat feeds</p>
                          </div>
                        </div>
                        <Switch defaultChecked />
                      </div>
                      
                      <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                        <div className="flex items-center">
                          <div className="w-10 h-10 bg-purple-500/10 rounded-full flex items-center justify-center text-purple-500 mr-4">
                            <Lock className="h-5 w-5" />
                          </div>
                          <div>
                            <h4 className="font-medium">SSO Provider</h4>
                            <p className="text-sm text-muted-foreground">Single sign-on authentication</p>
                          </div>
                        </div>
                        <Switch />
                      </div>
                    </div>
                  </CardContent>
                  <CardFooter>
                    <Button className="ml-auto" onClick={handleSaveChanges}>Save Changes</Button>
                  </CardFooter>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
          {/* Render the 2FA Setup Dialog */}
          <TwoFactorAuthSetupDialog 
            isOpen={isTwoFactorAuthDialogOpen}
            onClose={() => setIsTwoFactorAuthDialogOpen(false)}
            onSuccess={handle2FASuccess}
          />

          {/* Render the Change Password Dialog */}
          <ChangePasswordDialog
            isOpen={isChangePasswordDialogOpen}
            onClose={() => setIsChangePasswordDialogOpen(false)}
          />
        </main>
      </div>
    </div>
  );
};

export default Settings;
