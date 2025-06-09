// eCyber/src/components/TwoFactorAuthSettings.tsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '@/context/AuthContext';
import { apiClient, generate2FASecret, enable2FA, disable2FA } from '@/services/api'; // Assuming apiClient is not directly needed here if other functions are used
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import QRCode from 'react-qr-code'; // Changed import

const TwoFactorAuthSettings = () => {
  const { user, fetchUserProfile, updateUser2FAStatus } = useAuth();
  const { toast } = useToast();

  const [isLoading, setIsLoading] = useState(false);
  const [setupStage, setSetupStage] = useState<'idle' | 'generated' | 'enabling'>('idle'); // 'idle', 'generated' (secret shown), 'enabling'
  const [twoFactorSecret, setTwoFactorSecret] = useState<string | null>(null);
  const [qrCodeUri, setQrCodeUri] = useState<string | null>(null);
  const [otpCode, setOtpCode] = useState('');

  const handleGenerateSecret = async () => {
    setIsLoading(true);
    try {
      const response = await generate2FASecret();
      setTwoFactorSecret(response.secret);
      setQrCodeUri(response.qr_code_uri);
      setSetupStage('generated');
      toast({ title: '2FA Secret Generated', description: 'Scan the QR code with your authenticator app.' });
    } catch (error: any) {
      toast({ title: 'Error Generating Secret', description: error.response?.data?.detail || error.message, variant: 'destructive' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleEnable2FA = async () => {
    if (!otpCode || otpCode.length !== 6) {
      toast({ title: 'Invalid Code', description: 'Please enter a 6-digit OTP code.', variant: 'destructive' });
      return;
    }
    setIsLoading(true);
    setSetupStage('enabling');
    try {
      await enable2FA({ code: otpCode });
      toast({ title: '2FA Enabled Successfully!', variant: 'default' });
      setSetupStage('idle');
      setOtpCode('');
      setTwoFactorSecret(null);
      setQrCodeUri(null);
      // Update global user state
      if (user) updateUser2FAStatus(true); // Optimistic update
      await fetchUserProfile(); // Or fetchUserProfile to get confirmed server state
    } catch (error: any) {
      toast({ title: 'Error Enabling 2FA', description: error.response?.data?.detail || 'Invalid OTP code or server error.', variant: 'destructive' });
    } finally {
      setIsLoading(false);
      if (setupStage === 'enabling') setSetupStage('generated'); // Revert to generated if enabling failed to allow retry
    }
  };

  const handleDisable2FA = async () => {
    setIsLoading(true);
    try {
      await disable2FA();
      toast({ title: '2FA Disabled Successfully', variant: 'default' });
      // Update global user state
      if (user) updateUser2FAStatus(false); // Optimistic update
      await fetchUserProfile(); // Or fetchUserProfile
    } catch (error: any) {
      toast({ title: 'Error Disabling 2FA', description: error.response?.data?.detail || error.message, variant: 'destructive' });
    } finally {
      setIsLoading(false);
    }
  };
  
  if (!user) {
    return <p>Loading user information...</p>;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Two-Factor Authentication (2FA)</CardTitle>
        <CardDescription>
          {user.is_two_factor_enabled 
            ? '2FA is currently enabled for your account.' 
            : 'Enhance your account security by enabling 2FA.'}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {!user.is_two_factor_enabled && setupStage === 'idle' && (
          <Button onClick={handleGenerateSecret} disabled={isLoading}>
            {isLoading ? 'Generating...' : 'Setup 2FA'}
          </Button>
        )}

        {!user.is_two_factor_enabled && setupStage === 'generated' && qrCodeUri && twoFactorSecret && (
          <div className="space-y-4">
            <div>
              <p className="mb-2 font-semibold">1. Scan this QR Code:</p>
              <div className="p-4 bg-white inline-block rounded-lg">
                <QRCode value={qrCodeUri} size={200} />
              </div>
            </div>
            <div>
              <p className="mb-1 font-semibold">Or, manually enter this secret:</p>
              <p className="font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded inline-block">{twoFactorSecret}</p>
            </div>
            <div>
              <Label htmlFor="otpCode" className="font-semibold">2. Enter 6-digit code from your authenticator app:</Label>
              <Input 
                id="otpCode" 
                value={otpCode} 
                onChange={(e) => setOtpCode(e.target.value)}
                maxLength={6}
                placeholder="123456"
                className="w-full max-w-xs mt-1"
              />
            </div>
            <div className="flex space-x-2">
              <Button onClick={handleEnable2FA} disabled={isLoading || otpCode.length !== 6}>
                {isLoading && setupStage === 'enabling' ? 'Enabling...' : 'Enable 2FA'}
              </Button>
              <Button variant="outline" onClick={() => { setSetupStage('idle'); setOtpCode(''); setTwoFactorSecret(null); setQrCodeUri(null);}} disabled={isLoading}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {user.is_two_factor_enabled && (
          <Button onClick={handleDisable2FA} variant="destructive" disabled={isLoading}>
            {isLoading ? 'Disabling...' : 'Disable 2FA'}
          </Button>
        )}
      </CardContent>
      <CardFooter>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Use an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator.
        </p>
      </CardFooter>
    </Card>
  );
};

export default TwoFactorAuthSettings;