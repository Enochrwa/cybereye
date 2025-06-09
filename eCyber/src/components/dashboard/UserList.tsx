// eCyber/src/components/dashboard/UserList.tsx
import React, { useEffect, useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { getUsers } from '@/services/api'; // Actual API function

// Define a User type/interface based on your UserSchema
interface User { // This interface is also defined in api.ts, consider centralizing it
  id: number;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string; // Assuming string representation from API
}

export const UserList = () => {
  const { toast } = useToast();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  // Add pagination state if needed in future:
  // const [currentPage, setCurrentPage] = useState(1);
  // const [totalPages, setTotalPages] = useState(1);
  // const usersPerPage = 10;

  useEffect(() => {
    const fetchUsers = async () => {
      setIsLoading(true);
      try {
        const fetchedUsers = await getUsers(0, 10); // Actual API call
        setUsers(fetchedUsers);
        // if (response.total) { ... pagination logic ... } // getUsers currently returns User[] directly
      } catch (error: any) {
        const detail = error.response?.data?.detail || error.message || "Could not fetch users.";
        toast({ title: "Error", description: detail, variant: "destructive" });
      } finally {
        setIsLoading(false);
      }
    };

    fetchUsers();
  }, [toast]);

  if (isLoading) {
    return <p>Loading users...</p>; // Or a more sophisticated loader/skeleton
  }

  if (!users.length) {
    return <p>No users found.</p>;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>System Users</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Full Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Joined</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id}>
                <TableCell className="font-medium">{user.username}</TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>{user.full_name || '-'}</TableCell>
                <TableCell>
                  <Badge variant={user.is_active ? "default" : "outline"} className={user.is_active ? 'bg-green-500 text-white' : 'border-red-500 text-red-500'}>
                    {user.is_active ? "Active" : "Inactive"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={user.is_superuser ? "secondary" : "outline"}>
                    {user.is_superuser ? "Admin" : "User"}
                  </Badge>
                </TableCell>
                <TableCell>{new Date(user.created_at).toLocaleDateString()}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {/* Add Pagination controls here if implementing full pagination */}
      </CardContent>
    </Card>
  );
};
