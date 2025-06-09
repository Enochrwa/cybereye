import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import QRCode from 'react-qr-code'; // ✅ Updated import
import { useAuth } from '@/context/AuthContext';
import { generate2FASecret, enable2FA } from '@/services/api';

interface TwoFactorAuthSetupDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const TwoFactorAuthSetupDialog: React.FC<TwoFactorAuthSetupDialogProps> = ({ isOpen, onClose, onSuccess }) => {
  const { toast } = useToast();
  const { fetchUserProfile, updateUser2FAStatus } = useAuth();
  const [secret, setSecret] = useState<string | null>(null);
  const [qrCodeUri, setQrCodeUri] = useState<string | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setSecret(null);
      setQrCodeUri(null);
      setVerificationCode('');
      setIsGenerating(true);
      
      const fetchSecret = async () => {
        try {
          const response = await generate2FASecret();
          setSecret(response.secret);
          setQrCodeUri(response.qr_code_uri);
        } catch (error: any) {
          const detail = error.response?.data?.detail || error.message || "Could not fetch 2FA secret.";
          toast({ title: "Error", description: detail, variant: "destructive" });
          onClose();
        } finally {
          setIsGenerating(false);
        }
      };

      fetchSecret();
    }
  }, [isOpen, onClose, toast]);

  const handleEnable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verificationCode || !secret) {
      toast({ title: "Error", description: "Missing verification code or secret.", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      await enable2FA({ verification_code: verificationCode, secret });
      await fetchUserProfile();
      updateUser2FAStatus(true);
      toast({ title: "Success", description: "Two-factor authentication enabled." });
      onSuccess();
      onClose();
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || "Could not enable 2FA.";
      toast({ title: "Error", description: detail, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Set Up Two-Factor Authentication</DialogTitle>
          <DialogDescription>
            Scan the QR code below with your authenticator app and enter the verification code to enable 2FA.
          </DialogDescription>
        </DialogHeader>

        {isGenerating ? (
          <p className="text-center text-sm text-muted-foreground">Generating QR Code...</p>
        ) : (
          qrCodeUri && (
            <div className="flex justify-center py-4">
              <QRCode value={qrCodeUri} size={160} />
            </div>
          )
        )}

        <form onSubmit={handleEnable2FA}>
          <div className="space-y-4">
            <div>
              <Label htmlFor="verificationCode">Verification Code</Label>
              <Input
                id="verificationCode"
                placeholder="Enter code from your app"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
              />
            </div>
          </div>

          <DialogFooter className="mt-4">
            <Button type="submit" disabled={isLoading || isGenerating}>
              {isLoading ? "Enabling..." : "Enable 2FA"}
            </Button>
            <Button variant="outline" type="button" onClick={onClose}>
              Cancel
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};
