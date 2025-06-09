// Fixed AuthContext with improved error handling and token management
import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient, getAuthToken, storeAuthToken, removeAuthToken, type User } from '@/services/api';
import { setAuthModalState } from '@/app/slices/displaySlice';
import { useDispatch } from 'react-redux';
import { isDebugEnabled } from '@/config';

interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
  login: (credentials: { username: string; password: string }) => Promise<{ success: boolean; requires2FA?: boolean; error?: string }>;
  verify2FA: (code: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  fetchUserProfile: () => Promise<void>;
  updateUser2FAStatus: (isEnabled: boolean) => void;
  clearError: () => void;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

// Auth provider component
export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tempToken, setTempToken] = useState<string | null>(null); // For 2FA flow
  
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Clear error
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Fetch user profile
  const fetchUserProfile = useCallback(async (): Promise<void> => {
    if (!token) return;

    try {
      setIsLoading(true);
      const userData = await apiClient.getCurrentUser();
      setUser(userData);
      setError(null);
      
      if (isDebugEnabled) {
        console.log('✅ User profile fetched:', userData);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch user profile';
      setError(errorMessage);
      console.error('Failed to fetch user profile:', err);
      
      // If token is invalid, clear auth state
      if (errorMessage.includes('401') || errorMessage.includes('unauthorized')) {
        await logout();
      }
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  // Login function
  const login = useCallback(async (credentials: { username: string; password: string }) => {
    try {
      setIsLoading(true);
      setError(null);

      const response = await apiClient.login(credentials);
      
      if (response.is_2fa_required) {
        // Store temporary token for 2FA verification
        setTempToken(response.access_token);
        return { success: true, requires2FA: true };
      } else {
        // Complete login
        storeAuthToken(response.access_token, response.expires_in);
        setToken(response.access_token);
        
        // Fetch user data if provided, otherwise fetch from API
        if (response.user) {
          setUser(response.user);
        } else {
          await fetchUserProfile();
        }
        
        if (isDebugEnabled) {
          console.log('✅ Login successful');
        }
        
        return { success: true };
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setError(errorMessage);
      console.error('Login failed:', err);
      return { success: false, error: errorMessage };
    } finally {
      setIsLoading(false);
    }
  }, [fetchUserProfile]);

  // 2FA verification
  const verify2FA = useCallback(async (code: string) => {
    if (!tempToken) {
      const errorMessage = 'No temporary token available for 2FA verification';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }

    try {
      setIsLoading(true);
      setError(null);

      // Temporarily set token for 2FA request
      const originalToken = token;
      setToken(tempToken);
      
      const response = await apiClient.verify2FA(code);
      
      // Store the final token
      storeAuthToken(response.access_token, response.expires_in);
      setToken(response.access_token);
      setTempToken(null);
      
      // Fetch user profile
      await fetchUserProfile();
      
      if (isDebugEnabled) {
        console.log('✅ 2FA verification successful');
      }
      
      return { success: true };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : '2FA verification failed';
      setError(errorMessage);
      console.error('2FA verification failed:', err);
      
      // Restore original token state
      setToken(token);
      
      return { success: false, error: errorMessage };
    } finally {
      setIsLoading(false);
    }
  }, [tempToken, token, fetchUserProfile]);

  // Logout function
  const logout = useCallback(async (): Promise<void> => {
    try {
      // Call logout endpoint if token exists
      if (token) {
        await apiClient.logout();
      }
    } catch (err) {
      console.error('Logout API call failed:', err);
      // Continue with local logout even if API call fails
    } finally {
      // Clear local state
      removeAuthToken();
      setToken(null);
      setUser(null);
      setTempToken(null);
      setError(null);
      
      if (isDebugEnabled) {
        console.log('✅ Logout completed');
      }
      
      // Navigate to home page
      navigate('/');
    }
  }, [token, navigate]);

  // Update user 2FA status
  const updateUser2FAStatus = useCallback((isEnabled: boolean) => {
    if (user) {
      setUser({ ...user, is_two_factor_enabled: isEnabled });
    }
  }, [user]);

  // Refresh authentication
  const refreshAuth = useCallback(async (): Promise<void> => {
    const currentToken = getAuthToken();
    if (currentToken) {
      setToken(currentToken);
      await fetchUserProfile();
    } else {
      setIsLoading(false);
    }
  }, [fetchUserProfile]);

  // Initialize auth state
  useEffect(() => {
    const initializeAuth = async () => {
      const currentToken = getAuthToken();
      
      if (currentToken) {
        setToken(currentToken);
        await fetchUserProfile();
      } else {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, [fetchUserProfile]);

  // Listen for auth events
  useEffect(() => {
    const handleAuthLogout = () => {
      logout();
    };

    window.addEventListener('auth:logout', handleAuthLogout);
    
    return () => {
      window.removeEventListener('auth:logout', handleAuthLogout);
    };
  }, [logout]);

  // Auto-redirect after successful login
  useEffect(() => {
    if (user && token && !tempToken) {
      // Only redirect if we're on the home page
      if (window.location.pathname === '/') {
        navigate('/dashboard');
      }
    }
  }, [user, token, tempToken, navigate]);

  const value: AuthState = {
    user,
    token,
    isLoading,
    isAuthenticated: !!user && !!token && !tempToken,
    error,
    login,
    verify2FA,
    logout,
    fetchUserProfile,
    updateUser2FAStatus,
    clearError,
    refreshAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Hook to use auth context
export const useAuth = (): AuthState => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;

