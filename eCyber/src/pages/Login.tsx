// eCyber/src/pages/Login.tsx
import React, { useEffect, useState } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from 'react-router-dom'; // ✅ Replaces useRouter from Next.js
import { useAuth } from '@/context/AuthContext';
import { loginUser, verifyTwoFactor, storeAuthToken } from '@/services/api';

const LoginPage = () => {
  const { toast } = useToast();
  const { login: contextLogin, isAuthenticated } = useAuth(); // Avoid naming conflict
  const navigate = useNavigate(); // ✅ React Router's navigation hook

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  
  const [isLoading, setIsLoading] = useState(false);
  const [showTwoFactorForm, setShowTwoFactorForm] = useState(false);
  const [userIdFor2FA, setUserIdFor2FA] = useState<number | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard'); // ✅ Replaces router.push
    }
  }, [isAuthenticated, navigate]);

  const handleLoginSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsLoading(true);
    try {
      const response = await loginUser({ username, password });
      if (response.is_2fa_required) {
        setUserIdFor2FA(response.userId);
        setShowTwoFactorForm(true);
        toast({ title: "2FA Required", description: "Please enter your 2FA code." });
        if (response.access_token) storeAuthToken(response.access_token);
      } else {
        await contextLogin(response.access_token);
        navigate('/dashboard');
      }
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || "Login failed.";
      toast({ title: "Login Error", description: detail, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleTwoFactorSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsLoading(true);
    try {
      if (userIdFor2FA === null) throw new Error("User ID for 2FA not found.");
      const response = await verifyTwoFactor({ userId: userIdFor2FA, code: twoFactorCode });
      await contextLogin(response.access_token);
      navigate('/dashboard');
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || "2FA verification failed.";
      toast({ title: "2FA Error", description: detail, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-background p-4">
      <Card className="w-full max-w-md">
        <form onSubmit={showTwoFactorForm ? handleTwoFactorSubmit : handleLoginSubmit}>
          <CardHeader>
            <CardTitle className="text-2xl">Login</CardTitle>
            <CardDescription>
              {showTwoFactorForm ? "Enter your two-factor authentication code." : "Enter your credentials to access your account."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!showTwoFactorForm ? (
              <>
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    type="text"
                    placeholder="Enter your username"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="Enter your password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
              </>
            ) : (
              <div className="space-y-2">
                <Label htmlFor="2fa">2FA Code</Label>
                <Input
                  id="2fa"
                  type="text"
                  placeholder="Enter 2FA code"
                  required
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value)}
                />
              </div>
            )}
          </CardContent>
          <CardFooter>
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Processing..." : showTwoFactorForm ? "Verify 2FA" : "Login"}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
};

export default LoginPage;
