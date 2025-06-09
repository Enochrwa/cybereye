
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { Shield, UserPlus } from 'lucide-react';

interface UserFormProps {
  onUserAdded: (user: any) => void;
  onCancel?: () => void;
}

const UserForm: React.FC<UserFormProps> = ({ onUserAdded, onCancel }) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    role: '',
    permissions: {
      read: true,
      write: false,
      delete: false,
      admin: false,
    }
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const { toast } = useToast();
  
  const handleChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };
  
  const handlePermissionChange = (permission: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      permissions: {
        ...prev.permissions,
        [permission]: checked
      }
    }));
  };
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validation
    if (!formData.name || !formData.email || !formData.role) {
      toast({
        title: "Validation Error",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      toast({
        title: "Validation Error",
        description: "Please enter a valid email address",
        variant: "destructive",
      });
      return;
    }
    
    setIsSubmitting(true);
    
    // Simulate API call
    setTimeout(() => {
      const newUser = {
        id: Date.now(),
        name: formData.name,
        email: formData.email,
        role: formData.role,
        status: 'active',
        lastLogin: new Date(),
        permissions: Object.entries(formData.permissions)
          .filter(([_, enabled]) => enabled)
          .map(([perm]) => perm),
      };
      
      onUserAdded(newUser);
      
      toast({
        title: "User Added",
        description: `${formData.name} has been added successfully`,
      });
      
      // Reset form
      setFormData({
        name: '',
        email: '',
        role: '',
        permissions: {
          read: true,
          write: false,
          delete: false,
          admin: false,
        }
      });
      
      setIsSubmitting(false);
    }, 1000);
  };
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center">
          <UserPlus className="mr-2 h-5 w-5" />
          Add New User
        </CardTitle>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input 
                id="name" 
                value={formData.name} 
                onChange={(e) => handleChange('name', e.target.value)}
                placeholder="John Smith"
                required
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input 
                id="email" 
                type="email"
                value={formData.email} 
                onChange={(e) => handleChange('email', e.target.value)}
                placeholder="john@example.com"
                required
              />
            </div>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="role">Role</Label>
            <Select 
              value={formData.role} 
              onValueChange={(value) => handleChange('role', value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select a role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Administrator">Administrator</SelectItem>
                <SelectItem value="Security Analyst">Security Analyst</SelectItem>
                <SelectItem value="Network Engineer">Network Engineer</SelectItem>
                <SelectItem value="IT Support">IT Support</SelectItem>
                <SelectItem value="End User">End User</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div className="space-y-2">
            <Label>Permissions</Label>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="read-permission" 
                  checked={formData.permissions.read}
                  onCheckedChange={(checked) => handlePermissionChange('read', checked as boolean)}
                />
                <Label htmlFor="read-permission">Read Access</Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="write-permission" 
                  checked={formData.permissions.write}
                  onCheckedChange={(checked) => handlePermissionChange('write', checked as boolean)}
                />
                <Label htmlFor="write-permission">Write Access</Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="delete-permission" 
                  checked={formData.permissions.delete}
                  onCheckedChange={(checked) => handlePermissionChange('delete', checked as boolean)}
                />
                <Label htmlFor="delete-permission">Delete Access</Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="admin-permission" 
                  checked={formData.permissions.admin}
                  onCheckedChange={(checked) => handlePermissionChange('admin', checked as boolean)}
                />
                <Label htmlFor="admin-permission">Admin Access</Label>
              </div>
            </div>
          </div>
          
          <div className="pt-2 border-t border-border">
            <div className="flex items-center space-x-2 text-sm">
              <Shield className="h-4 w-4 text-amber-500" />
              <span className="text-muted-foreground">
                A temporary password will be generated and sent to the user's email
              </span>
            </div>
          </div>
        </CardContent>
        <CardFooter className="flex justify-between">
          {onCancel && (
            <Button type="button" variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Adding User...' : 'Add User'}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
};

export default UserForm;
