// Fixed API client with proper error handling and token management
import axios, { AxiosInstance, AxiosError, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import config, { isDebugEnabled } from '@/config';

// Types
interface LoginResponse {
  access_token: string;
  token_type: string;
  is_2fa_required?: boolean;
  user_id?: number;
  expires_in?: number;
  user?: User;
}

interface Verify2FAResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
}

interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string | null;
  is_active: boolean;
  is_superuser: boolean;
  is_two_factor_enabled?: boolean;
  created_at: string;
  updated_at?: string;
}

interface ApiError {
  detail: string;
  code?: string;
  field?: string;
}

// Token management
class TokenManager {
  private static readonly TOKEN_KEY = 'ecyber_auth_token';
  private static readonly REFRESH_TOKEN_KEY = 'ecyber_refresh_token';
  private static readonly TOKEN_EXPIRY_KEY = 'ecyber_token_expiry';

  static getToken(): string | null {
    try {
      return localStorage.getItem(this.TOKEN_KEY);
    } catch (error) {
      console.error('Error getting token from localStorage:', error);
      return null;
    }
  }

  static setToken(token: string, expiresIn?: number): void {
    try {
      localStorage.setItem(this.TOKEN_KEY, token);
      
      if (expiresIn) {
        const expiryTime = Date.now() + (expiresIn * 1000);
        localStorage.setItem(this.TOKEN_EXPIRY_KEY, expiryTime.toString());
      }
    } catch (error) {
      console.error('Error setting token in localStorage:', error);
    }
  }

  static removeToken(): void {
    try {
      localStorage.removeItem(this.TOKEN_KEY);
      localStorage.removeItem(this.REFRESH_TOKEN_KEY);
      localStorage.removeItem(this.TOKEN_EXPIRY_KEY);
    } catch (error) {
      console.error('Error removing token from localStorage:', error);
    }
  }

  static isTokenExpired(): boolean {
    try {
      const expiryTime = localStorage.getItem(this.TOKEN_EXPIRY_KEY);
      if (!expiryTime) return false;
      
      return Date.now() > parseInt(expiryTime);
    } catch (error) {
      console.error('Error checking token expiry:', error);
      return true;
    }
  }

  static getRefreshToken(): string | null {
    try {
      return localStorage.getItem(this.REFRESH_TOKEN_KEY);
    } catch (error) {
      console.error('Error getting refresh token:', error);
      return null;
    }
  }

  static setRefreshToken(token: string): void {
    try {
      localStorage.setItem(this.REFRESH_TOKEN_KEY, token);
    } catch (error) {
      console.error('Error setting refresh token:', error);
    }
  }
}

// API Client class
class ApiClient {
  private client: AxiosInstance;
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (value: any) => void;
    reject: (error: any) => void;
  }> = [];

  constructor() {
    this.client = axios.create({
      baseURL: config.apiBaseUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const token = TokenManager.getToken();
        
        if (token && !TokenManager.isTokenExpired()) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        if (isDebugEnabled) {
          console.log('🚀 API Request:', {
            method: config.method?.toUpperCase(),
            url: config.url,
            data: config.data,
          });
        }

        return config;
      },
      (error) => {
        console.error('Request interceptor error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        if (isDebugEnabled) {
          console.log('✅ API Response:', {
            status: response.status,
            url: response.config.url,
            data: response.data,
          });
        }
        return response;
      },
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        if (isDebugEnabled) {
          console.error('❌ API Error:', {
            status: error.response?.status,
            url: error.config?.url,
            message: error.message,
            data: error.response?.data,
          });
        }

        // Handle 401 errors (unauthorized)
        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            // If already refreshing, queue the request
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject });
            }).then(token => {
              originalRequest.headers.Authorization = `Bearer ${token}`;
              return this.client(originalRequest);
            }).catch(err => {
              return Promise.reject(err);
            });
          }

          originalRequest._retry = true;
          this.isRefreshing = true;

          try {
            const refreshToken = TokenManager.getRefreshToken();
            if (refreshToken) {
              const response = await this.refreshToken();
              const { access_token } = response;
              
              TokenManager.setToken(access_token);
              
              // Process failed queue
              this.processQueue(null, access_token);
              
              // Retry original request
              originalRequest.headers.Authorization = `Bearer ${access_token}`;
              return this.client(originalRequest);
            } else {
              throw new Error('No refresh token available');
            }
          } catch (refreshError) {
            this.processQueue(refreshError, null);
            TokenManager.removeToken();
            
            // Redirect to login or emit logout event
            window.dispatchEvent(new CustomEvent('auth:logout'));
            
            return Promise.reject(refreshError);
          } finally {
            this.isRefreshing = false;
          }
        }

        return Promise.reject(this.handleError(error));
      }
    );
  }

  private processQueue(error: any, token: string | null): void {
    this.failedQueue.forEach(({ resolve, reject }) => {
      if (error) {
        reject(error);
      } else {
        resolve(token);
      }
    });
    
    this.failedQueue = [];
  }

  private handleError(error: AxiosError): Error {
    if (error.response) {
      const apiError = error.response.data as ApiError;
      return new Error(apiError.detail || 'An error occurred');
    } else if (error.request) {
      return new Error('Network error - please check your connection');
    } else {
      return new Error(error.message || 'An unexpected error occurred');
    }
  }

  // Authentication methods
  async login(credentials: { username: string; password: string }): Promise<LoginResponse> {
    const formData = new URLSearchParams();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);

    const response = await this.client.post<LoginResponse>('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    return response.data;
  }

  

  async verify2FA(code: string): Promise<Verify2FAResponse> {
    const response = await this.client.post<Verify2FAResponse>('/auth/verify-2fa', { code });
    return response.data;
  }

  async refreshToken(): Promise<{ access_token: string }> {
    const response = await this.client.post<{ access_token: string }>('/auth/refresh');
    return response.data;
  }

  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<User>('/auth/me');
    return response.data;
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } finally {
      TokenManager.removeToken();
    }
  }

  // 2FA Management
  async generate2FASecret(): Promise<{ secret: string; qr_code_uri: string }> {
    const response = await this.client.post('/auth/2fa/generate-secret');
    return response.data;
  }

  async enable2FA(code: string): Promise<{ message: string }> {
    const response = await this.client.post('/auth/2fa/enable', { code });
    return response.data;
  }

  async disable2FA(): Promise<{ message: string }> {
    const response = await this.client.post('/auth/2fa/disable');
    return response.data;
  }

  // User management
  async getUsers(skip: number = 0, limit: number = 10): Promise<User[]> {
    const response = await this.client.get<User[]>('/users', { 
      params: { skip, limit } 
    });
    return response.data;
  }

  async changePassword(data: { current_password: string; new_password: string }): Promise<{ message: string }> {
    const response = await this.client.post('/auth/change-password', data);
    return response.data;
  }

  // Generic methods
  async get<T>(url: string, params?: any): Promise<T> {
    const response = await this.client.get<T>(url, { params });
    return response.data;
  }

  async post<T>(url: string, data?: any): Promise<T> {
    const response = await this.client.post<T>(url, data);
    return response.data;
  }

  async put<T>(url: string, data?: any): Promise<T> {
    const response = await this.client.put<T>(url, data);
    return response.data;
  }

  async delete<T>(url: string): Promise<T> {
    const response = await this.client.delete<T>(url);
    return response.data;
  }

  // Health check
  async healthCheck(): Promise<{ status: string; timestamp: string; version: string }> {
    const response = await this.client.get('/health');
    return response.data;
  }
}

// Create and export API client instance
export const apiClient = new ApiClient();

// Export token management functions
export const getAuthToken = TokenManager.getToken;
export const storeAuthToken = (token: string, expiresIn?: number) => {
  TokenManager.setToken(token, expiresIn);
};
export const removeAuthToken = TokenManager.removeToken;

// Export types
export type { LoginResponse, Verify2FAResponse, User, ApiError };

// Legacy exports for backward compatibility
export const loginUser = (credentials: { username: string; password: string }) => 
  apiClient.login(credentials);

export const registerUser = async (userData: any) => {
  const response = await axios.post('httpp://127.0.0.1:8000/auth/register', userData);
  return response.data; // Expected: UserSchema
};

export const verifyTwoFactorLogin = (code: string) => 
  apiClient.verify2FA(code);

export const generate2FASecret = () => 
  apiClient.generate2FASecret();

export const enable2FA = (code: string) => 
  apiClient.enable2FA(code);

export const disable2FA = () => 
  apiClient.disable2FA();

export const getUsers = (skip?: number, limit?: number) => 
  apiClient.getUsers(skip, limit);

export const changePassword = (data: { current_password: string; new_password: string }) => 
  apiClient.changePassword(data);

export default apiClient;

