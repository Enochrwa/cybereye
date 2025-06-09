
import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Users as UsersIcon, UserPlus, Search, UserCheck, Shield, ArrowRight, Pencil } from 'lucide-react';
import { Input } from "@/components/ui/input";
import Header from '../components/layout/Header';
import UserForm from '../components/users/UserForm';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

// Sample users data
const initialUsers = [
  {
    id: 1,
    name: "John Smith",
    email: "john.smith@example.com",
    role: "Administrator",
    status: "active",
    lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000),
    permissions: ["read", "write", "delete", "admin"],
  },
  {
    id: 2,
    name: "Sarah Johnson",
    email: "sarah.j@example.com",
    role: "Security Analyst",
    status: "active",
    lastLogin: new Date(Date.now() - 8 * 60 * 60 * 1000),
    permissions: ["read", "write"],
  },
  {
    id: 3,
    name: "Michael Brown",
    email: "m.brown@example.com",
    role: "Network Engineer",
    status: "active",
    lastLogin: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    permissions: ["read", "write"],
  },
  {
    id: 4,
    name: "Lisa Chen",
    email: "lisa.chen@example.com",
    role: "Security Analyst",
    status: "offline",
    lastLogin: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
    permissions: ["read", "write"],
  },
  {
    id: 5,
    name: "David Wilson",
    email: "d.wilson@example.com",
    role: "IT Support",
    status: "locked",
    lastLogin: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
    permissions: ["read"],
  },
];

// User role definitions
const roleDefinitions = [
  {
    name: "Administrator",
    description: "Full access to all system features and settings",
    permissions: ["read", "write", "delete", "admin"],
    userCount: 2
  },
  {
    name: "Security Analyst",
    description: "Can view and analyze security events and logs",
    permissions: ["read", "write"],
    userCount: 8
  },
  {
    name: "Network Engineer",
    description: "Manages network configuration and monitoring",
    permissions: ["read", "write"],
    userCount: 5
  },
  {
    name: "IT Support",
    description: "Basic system access for troubleshooting",
    permissions: ["read"],
    userCount: 10
  },
  {
    name: "End User",
    description: "Limited access to specific features",
    permissions: ["read"],
    userCount: 170
  }
];

const Users = () => {
  const [users, setUsers] = useState(initialUsers);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddUserForm, setShowAddUserForm] = useState(false);
  const { toast } = useToast();
  
  const filteredUsers = users.filter(user => {
    const term = searchTerm.toLowerCase();
    return (
      user.name.toLowerCase().includes(term) ||
      user.email.toLowerCase().includes(term) ||
      user.role.toLowerCase().includes(term)
    );
  });
  
  const handleAddUser = (newUser: any) => {
    setUsers(prev => [...prev, newUser]);
    setShowAddUserForm(false);
  };
  
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value);
  };
  
  const handleUserAction = (action: string, user: any) => {
    switch (action) {
      case 'permissions':
        toast({
          title: "Managing Permissions",
          description: `Editing permissions for ${user.name}`,
        });
        break;
      case 'status':
        const newStatus = user.status === 'active' ? 'locked' : 'active';
        setUsers(prevUsers => 
          prevUsers.map(u => 
            u.id === user.id ? { ...u, status: newStatus } : u
          )
        );
        toast({
          title: "Status Updated",
          description: `${user.name} is now ${newStatus}`,
        });
        break;
    }
  };
  
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
     
      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Access Control</h1>
              <p className="text-muted-foreground">Manage user access and permissions</p>
            </div>
            
            <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
          
          {/* User statistics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <UsersIcon className="mr-2" size={16} />
                  User Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-muted/50 rounded-lg text-center">
                    <div className="text-2xl font-semibold">195</div>
                    <div className="text-xs text-muted-foreground mt-1">Total Users</div>
                  </div>
                  <div className="p-4 bg-muted/50 rounded-lg text-center">
                    <div className="text-2xl font-semibold">24</div>
                    <div className="text-xs text-muted-foreground mt-1">Online Now</div>
                  </div>
                  <div className="p-4 bg-muted/50 rounded-lg text-center">
                    <div className="text-2xl font-semibold">8</div>
                    <div className="text-xs text-muted-foreground mt-1">New (7 days)</div>
                  </div>
                  <div className="p-4 bg-muted/50 rounded-lg text-center">
                    <div className="text-2xl font-semibold">3</div>
                    <div className="text-xs text-muted-foreground mt-1">Locked Accounts</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <Shield className="mr-2" size={16} />
                  Roles Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {roleDefinitions.map((role, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <span className="text-sm">{role.name}</span>
                      <div className="flex items-center">
                        <div className="h-2 w-24 bg-muted rounded-full mr-2">
                          <div 
                            className="h-full bg-blue-500 rounded-full" 
                            style={{ width: `${(role.userCount / 195) * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-muted-foreground">{role.userCount}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center">
                  <UserCheck className="mr-2" size={16} />
                  Quick Actions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <Button className="w-full justify-start" size="sm" onClick={() => setShowAddUserForm(true)}>
                    <UserPlus className="mr-2 h-4 w-4" />
                    Add New User
                  </Button>
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button className="w-full justify-start" variant="outline" size="sm">
                        <Shield className="mr-2 h-4 w-4" />
                        Manage Roles
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="max-w-3xl">
                      <DialogHeader>
                        <DialogTitle>Role Management</DialogTitle>
                      </DialogHeader>
                      
                      <Tabs defaultValue="roles">
                        <TabsList>
                          <TabsTrigger value="roles">Role Definitions</TabsTrigger>
                          <TabsTrigger value="new">Create New Role</TabsTrigger>
                        </TabsList>
                        
                        <TabsContent value="roles" className="space-y-4 pt-4">
                          {roleDefinitions.map((role, index) => (
                            <div key={index} className="p-4 border border-border rounded-md">
                              <div className="flex justify-between">
                                <div>
                                  <h3 className="font-medium">{role.name}</h3>
                                  <p className="text-sm text-muted-foreground">{role.description}</p>
                                </div>
                                <Button variant="outline" size="sm">
                                  <Pencil className="h-4 w-4" />
                                </Button>
                              </div>
                              
                              <div className="mt-2 flex flex-wrap gap-1">
                                {role.permissions.map((perm, i) => (
                                  <Badge key={i} variant="secondary" className="text-xs">
                                    {perm}
                                  </Badge>
                                ))}
                              </div>
                              
                              <div className="mt-2 text-xs text-muted-foreground">
                                {role.userCount} users assigned
                              </div>
                            </div>
                          ))}
                        </TabsContent>
                        
                        <TabsContent value="new">
                          <div className="space-y-4 pt-4">
                            <p className="text-sm text-muted-foreground">
                              Create a new role with custom permissions
                            </p>
                            <Button onClick={() => toast({ title: "Feature Coming Soon", description: "Role creation will be available in the next update" })}>
                              Create Custom Role
                            </Button>
                          </div>
                        </TabsContent>
                      </Tabs>
                    </DialogContent>
                  </Dialog>
                  
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button className="w-full justify-start" variant="outline" size="sm">
                        <Shield className="mr-2 h-4 w-4" />
                        Review Permissions
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Permission Audit</DialogTitle>
                      </DialogHeader>
                      <div className="py-4">
                        <Button onClick={() => toast({ title: "Audit Started", description: "Permission audit in progress" })}>
                          Run Permission Audit
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </CardContent>
            </Card>
          </div>
          
          {/* Add User Form (conditional) */}
          {showAddUserForm && (
            <div className="mb-6">
              <UserForm 
                onUserAdded={handleAddUser} 
                onCancel={() => setShowAddUserForm(false)}
              />
            </div>
          )}
          
          {/* User list */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center">
                  <UsersIcon className="mr-2" size={18} />
                  Users
                </div>
                <div className="flex items-center space-x-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input 
                      placeholder="Search users..." 
                      className="pl-8 w-64" 
                      value={searchTerm}
                      onChange={handleSearch}
                    />
                  </div>
                  <Button onClick={() => setShowAddUserForm(true)}>
                    <UserPlus className="mr-2 h-4 w-4" />
                    Add User
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="border border-border rounded-md overflow-hidden">
                <div className="grid grid-cols-12 gap-4 p-3 bg-muted text-xs font-medium">
                  <div className="col-span-3">User</div>
                  <div className="col-span-3">Role</div>
                  <div className="col-span-2">Status</div>
                  <div className="col-span-2">Last Login</div>
                  <div className="col-span-2">Actions</div>
                </div>
                <div className="divide-y divide-border">
                  {filteredUsers.length === 0 ? (
                    <div className="p-6 text-center text-muted-foreground">
                      No users found matching "{searchTerm}"
                    </div>
                  ) : (
                    filteredUsers.map((user) => (
                      <div key={user.id} className="grid grid-cols-12 gap-4 p-3 text-sm hover:bg-muted/30">
                        <div className="col-span-3">
                          <div className="font-medium">{user.name}</div>
                          <div className="text-xs text-muted-foreground">{user.email}</div>
                        </div>
                        <div className="col-span-3">
                          <div className="flex items-center">
                            <Shield className="mr-1 h-3 w-3 text-muted-foreground" />
                            {user.role}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {user.permissions.map((perm, i) => (
                              <Badge key={i} variant="secondary" className="mr-1 text-[10px]">
                                {perm}
                              </Badge>
                            ))}
                          </div>
                        </div>
                        <div className="col-span-2">
                          <Badge className={cn(
                            user.status === "active" ? "bg-green-500/10 text-green-500" : 
                            user.status === "locked" ? "bg-red-500/10 text-red-500" :
                            "bg-muted text-muted-foreground"
                          )}>
                            {user.status}
                          </Badge>
                        </div>
                        <div className="col-span-2 text-muted-foreground">
                          {user.lastLogin.toLocaleDateString()}
                        </div>
                        <div className="col-span-2">
                          <div className="flex items-center space-x-1">
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              className="h-8 w-8"
                              onClick={() => handleUserAction('permissions', user)}
                            >
                              <Shield className="h-4 w-4" />
                            </Button>
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              className="h-8 w-8"
                              onClick={() => handleUserAction('status', user)}
                            >
                              <UserCheck className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <Button variant="ghost" size="sm" className="ml-auto">
                View All Users <ArrowRight className="ml-1" size={12} />
              </Button>
            </CardFooter>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Users;
