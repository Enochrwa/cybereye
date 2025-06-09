// eCyber/src/components/AuthModal.tsx
import React, { useState } from 'react';
import {
  Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle, DialogDescription
} from "@/components/ui/dialog";
import {
  Card, CardContent, CardFooter
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import {
  loginUser, registerUser, verifyTwoFactorLogin
} from "@/services/api";

import { RootState } from "@/app/store"
import { setAuthModalState} from "@/app/slices/displaySlice"
import { useSelector, useDispatch } from "react-redux"

const AuthModal = () => {
    const dispatch = useDispatch();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [userIdFor2FA, setUserIdFor2FA] = useState<number | null>(null);
  const [tempToken, setTempToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showTwoFactorForm, setShowTwoFactorForm] = useState(false);

  const { toast } = useToast();
  const navigate = useNavigate();
  const { login: contextLogin, isAuthenticated } = useAuth();

  const isAuthModalOpen = useSelector((state:RootState) => state.display.isAuthModalOpen)

  const resetFields = () => {
    setUsername('');
    setEmail('');
    setPassword('');
    setConfirmPassword('');
    setFullName('');
    setTwoFactorCode('');
    setUserIdFor2FA(null);
    setShowTwoFactorForm(false);
    setTempToken(null);
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      if (mode === 'login') {
        const response = await loginUser({ username, password });
        if (response.is_2fa_required && response.access_token && response.user_id !== undefined) {
          setUserIdFor2FA(response.user_id);
          setTempToken(response.access_token);
          setShowTwoFactorForm(true);
          toast({ title: "2FA Required", description: "Please enter your 2FA code." });
        } else if (response.access_token) {
          await contextLogin(response.access_token);
          navigate('/dashboard');
          dispatch(setAuthModalState(false));
          resetFields();
        } else {
          throw new Error("Invalid login response from server.");
        }
      } else {
        if (password !== confirmPassword) {
          toast({
            title: "Registration Failed",
            description: "Passwords do not match.",
            variant: "destructive",
          });
          setIsLoading(false);
          return;
        }
        await registerUser({ username, email, password, full_name: fullName });
        toast({ title: "Registration successful", description: "You can now log in." });
        setMode('login');
        resetFields();
      }
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || "Something went wrong.";
      toast({ title: "Error", description: detail });
    } finally {
      setIsLoading(false);
    }
  };

  const handle2FASubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    const currentTempToken = tempToken;

    if (!currentTempToken || userIdFor2FA === null) {
        toast({ title: "Error", description: "2FA session expired or invalid. Please try logging in again.", variant: "destructive" });
        setShowTwoFactorForm(false);
        setMode('login');
        resetFields();
        setIsLoading(false);
        return;
    }

    try {
      const response = await verifyTwoFactorLogin({ code: twoFactorCode, tempToken: currentTempToken });
      
      await contextLogin(response.access_token);
      
      navigate('/dashboard');
      dispatch(setAuthModalState(false));
      resetFields();
      
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || "2FA verification failed.";
      toast({ title: "2FA Error", description: detail, variant: "destructive" });
      setTwoFactorCode('');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Dialog open={isAuthModalOpen} onOpenChange={() => dispatch(setAuthModalState(!isAuthModalOpen))}>
        <DialogTrigger asChild>
          <button className="trigger-button relative px-8 py-3 transition-all duration-300 group overflow-hidden">
            <span className="relative z-10 flex items-center">
              <span className="status-indicator"></span>
              ACCESS TERMINAL
            </span>
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
          </button>
        </DialogTrigger>

        <DialogContent className="cyber-modal-overlay sm:max-w-[500px] border-0 bg-transparent p-0">
          <div className="cyber-container relative rounded-lg p-8">
            {/* Matrix Background */}
            <div className="matrix-bg">
              {Array.from({ length: 20 }, (_, i) => (
                <div
                  key={i}
                  className="matrix-char"
                  style={{
                    left: `${Math.random() * 100}%`,
                    animationDelay: `${Math.random() * 3}s`,
                    animationDuration: `${3 + Math.random() * 2}s`
                  }}
                >
                  {String.fromCharCode(0x30A0 + Math.random() * 96)}
                </div>
              ))}
            </div>
            
            {/* Scanning Line */}
            <div className="cyber-scanner"></div>
            
            <DialogHeader className="relative z-10 mb-8">
              <DialogTitle className="cyber-title text-2xl text-center mb-4">
                {showTwoFactorForm ? '⚡ NEURAL AUTHENTICATION ⚡' : mode === 'login' ? '🛡️ SECURE LOGIN 🛡️' : '⚔️ SYSTEM REGISTRATION ⚔️'}
              </DialogTitle>
              <DialogDescription className="cyber-description text-center">
                {showTwoFactorForm
                  ? "⟨ Biometric verification required - Enter your quantum security code ⟩"
                  : mode === 'login'
                    ? "⟨ Welcome back, cyber warrior. Initialize secure connection ⟩"
                    : "⟨ Join the digital resistance. Create your secure identity ⟩"}
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={showTwoFactorForm ? handle2FASubmit : handleAuth} className="form-section">
              <Card className="border-0 shadow-none bg-transparent">
                <CardContent className="space-y-6 p-0">
                  {!showTwoFactorForm && (
                    <>
                      <div className="space-y-3">
                        <Label htmlFor="username" className="cyber-label flex items-center gap-2">
                          <span className="text-cyan-400">👤</span> USER IDENTIFIER
                        </Label>
                        <div className="input-wrapper relative">
                          <Input
                            id="username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            className="cyber-input h-12 pl-4 pr-12 text-lg"
                            placeholder="Enter username..."
                          />
                          <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60">
                            ⟩
                          </div>
                        </div>
                      </div>

                      {mode === 'register' && (
                        <>
                          <div className="space-y-3">
                            <Label htmlFor="email" className="cyber-label flex items-center gap-2">
                              <span className="text-cyan-400">📧</span> NEURAL LINK ADDRESS
                            </Label>
                            <div className="input-wrapper relative">
                              <Input
                                id="email"
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                                className="cyber-input h-12 pl-4 pr-12 text-lg"
                                placeholder="Enter email address..."
                              />
                              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60">
                                ⟩
                              </div>
                            </div>
                          </div>
                          <div className="space-y-3">
                            <Label htmlFor="fullName" className="cyber-label flex items-center gap-2">
                              <span className="text-cyan-400">🧑</span> REALM IDENTITY
                            </Label>
                            <div className="input-wrapper relative">
                              <Input
                                id="fullName"
                                value={fullName}
                                onChange={(e) => setFullName(e.target.value)}
                                className="cyber-input h-12 pl-4 pr-12 text-lg"
                                placeholder="Enter your full name..."
                              />
                              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60">
                                ⟩
                              </div>
                            </div>
                          </div>
                        </>
                      )}

                      <div className="space-y-3">
                        <Label htmlFor="password" className="cyber-label flex items-center gap-2">
                          <span className="text-cyan-400">🔐</span> QUANTUM PASSPHRASE
                        </Label>
                        <div className="input-wrapper relative">
                          <Input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="cyber-input h-12 pl-4 pr-12 text-lg"
                            placeholder="Enter secure password..."
                          />
                          <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60">
                            🔒
                          </div>
                        </div>
                      </div>

                      {mode === 'register' && (
                        <div className="space-y-3">
                          <Label htmlFor="confirmPassword" className="cyber-label flex items-center gap-2">
                            <span className="text-cyan-400">🔐</span> REPEAT QUANTUM PASSPHRASE
                          </Label>
                          <div className="input-wrapper relative">
                            <Input
                              id="confirmPassword"
                              type="password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                              required
                              className="cyber-input h-12 pl-4 pr-12 text-lg"
                              placeholder="Confirm your secure password..."
                            />
                            <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60">
                              🔒
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}

                  {showTwoFactorForm && (
                    <div className="space-y-3">
                      <Label htmlFor="code" className="cyber-label flex items-center gap-2">
                        <span className="text-cyan-400 animate-pulse">🔐</span> BIOMETRIC CODE
                      </Label>
                      <div className="input-wrapper relative">
                        <Input
                          id="code"
                          value={twoFactorCode}
                          onChange={(e) => setTwoFactorCode(e.target.value)}
                          required
                          className="cyber-input h-12 pl-4 pr-12 text-lg text-center tracking-widest font-mono"
                          placeholder="⟨ ENTER 6-DIGIT CODE ⟩"
                          maxLength={6}
                        />
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyan-400 opacity-60 animate-pulse">
                          ⚡
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>

                <CardFooter className="flex flex-col items-center gap-6 p-0 mt-8">
                  <Button 
                    type="submit" 
                    className="cyber-button w-full h-14 text-lg relative"
                    disabled={isLoading}
                  >
                    <span className={`relative z-10 flex items-center justify-center gap-2 ${isLoading ? 'loading-dots' : ''}`}>
                      {isLoading && <span className="status-indicator"></span>}
                      {isLoading
                        ? 'PROCESSING'
                        : showTwoFactorForm
                          ? '⚡ VERIFY NEURAL SIGNATURE ⚡'
                          : mode === 'login' 
                            ? '🚀 INITIATE SECURE LOGIN 🚀' 
                            : '⚔️ CREATE WARRIOR PROFILE ⚔️'}
                    </span>
                  </Button>

                  {!showTwoFactorForm && (
                    <div className="text-center">
                      <p className="text-sm text-slate-300 font-mono">
                        {mode === 'login'
                          ? "⟨ New to the resistance? ⟩"
                          : "⟨ Already enlisted? ⟩"}{' '}
                        <span
                          className="cyber-link"
                          onClick={() => {
                            setMode(mode === 'login' ? 'register' : 'login');
                            resetFields();
                          }}
                        >
                          {mode === 'login' ? '⚡ REGISTER NOW ⚡' : '🚀 LOGIN HERE 🚀'}
                        </span>
                      </p>
                    </div>
                  )}
                </CardFooter>
              </Card>
            </form>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default AuthModal;