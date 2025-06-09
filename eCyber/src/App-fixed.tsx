// Fixed App component with better error handling and loading states
import React, { useEffect, useState, Suspense, lazy } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useSelector } from "react-redux";
import { RootState } from "@/app/store";
import { useAuth } from "./context/AuthContext";
import usePacketSniffer from "./hooks/usePacketSnifferSocket";
import config, { validateConfig, isDebugEnabled } from "@/config";

// Lazy load components for better performance
const Index = lazy(() => import("./pages/Index"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Threats = lazy(() => import("./pages/Threats"));
const Network = lazy(() => import("./pages/Network"));
const Logs = lazy(() => import("./pages/Logs"));
const Models = lazy(() => import("./pages/Models"));
const System = lazy(() => import("./components/live-system/System"));
const Users = lazy(() => import("./pages/Users"));
const Settings = lazy(() => import("./pages/Settings"));
const AttackSimulations = lazy(() => import("./pages/AttackSimulations"));
const MainLayout = lazy(() => import("./components/layout/MainLayout"));
const NotFound = lazy(() => import("./pages/NotFound"));
const ThreatCve = lazy(() => import("./pages/threats/ThreatCve"));
const ThreatMitre = lazy(() => import("./pages/threats/ThreatMitre"));
const ThreatIntel = lazy(() => import("./pages/threats/ThreatIntel"));
const ThreatOsint = lazy(() => import("./pages/threats/ThreatOsint"));
const Alerts = lazy(() => import("./alert/Alerts"));
const AuthModal = lazy(() => import("./pages/AuthModal"));

// Loading component
const LoadingSpinner: React.FC<{ message?: string }> = ({ message = "Loading..." }) => (
  <div className="flex items-center justify-center min-h-screen bg-background">
    <div className="flex flex-col items-center space-y-4">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      <p className="text-muted-foreground">{message}</p>
    </div>
  </div>
);

// Error boundary component
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('App Error Boundary caught an error:', error, errorInfo);
    
    // Report to error tracking service in production
    if (config.enableErrorReporting && !isDebugEnabled) {
      // Report error to monitoring service
      console.log('Would report error to monitoring service:', error);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-screen bg-background">
          <div className="text-center space-y-4 p-8">
            <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
            <p className="text-muted-foreground">
              An unexpected error occurred. Please refresh the page or contact support.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              Refresh Page
            </button>
            {isDebugEnabled && this.state.error && (
              <details className="mt-4 text-left">
                <summary className="cursor-pointer text-sm text-muted-foreground">
                  Error Details (Debug Mode)
                </summary>
                <pre className="mt-2 p-4 bg-muted rounded text-xs overflow-auto">
                  {this.state.error.stack}
                </pre>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Protected route component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <LoadingSpinner message="Checking authentication..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

// Connection status component
const ConnectionStatus: React.FC = () => {
  const { isConnected, connectionError, retryAttempts } = usePacketSniffer();
  const [showStatus, setShowStatus] = useState(false);

  useEffect(() => {
    // Show status when there are connection issues
    setShowStatus(!isConnected || !!connectionError);
  }, [isConnected, connectionError]);

  if (!showStatus) return null;

  return (
    <div className={`fixed top-0 left-0 right-0 z-50 p-2 text-center text-sm ${
      isConnected ? 'bg-green-500' : 'bg-red-500'
    } text-white`}>
      {isConnected ? (
        'Connected to server'
      ) : (
        <div>
          {connectionError || 'Connecting to server...'}
          {retryAttempts > 0 && ` (Attempt ${retryAttempts})`}
        </div>
      )}
    </div>
  );
};

// Main App component
const App: React.FC = () => {
  const [configError, setConfigError] = useState<string | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const isBackendUp = useSelector((state: RootState) => state.display.isBackendUp);
  const { isLoading: authLoading } = useAuth();

  // Initialize app
  useEffect(() => {
    const initializeApp = async () => {
      try {
        // Validate configuration
        validateConfig();
        
        if (isDebugEnabled) {
          console.log('🚀 eCyber Frontend initialized');
          console.log('📡 API Base URL:', config.apiBaseUrl);
          console.log('🔌 Socket URL:', config.socketUrl);
        }

        setIsInitialized(true);
      } catch (error) {
        console.error('Failed to initialize app:', error);
        setConfigError(error instanceof Error ? error.message : 'Configuration error');
      }
    };

    initializeApp();
  }, []);

  // Show configuration error
  if (configError) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="text-center space-y-4 p-8">
          <h1 className="text-2xl font-bold text-destructive">Configuration Error</h1>
          <p className="text-muted-foreground">{configError}</p>
          <p className="text-sm text-muted-foreground">
            Please check your environment configuration and try again.
          </p>
        </div>
      </div>
    );
  }

  // Show loading while initializing
  if (!isInitialized || authLoading) {
    return <LoadingSpinner message="Initializing eCyber..." />;
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-background">
        <ConnectionStatus />
        
        <Suspense fallback={<LoadingSpinner />}>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<Index />} />
            
            {/* Protected routes */}
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <MainLayout>
                  <Dashboard />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/system" element={
              <ProtectedRoute>
                <MainLayout>
                  <System />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/alerts" element={
              <ProtectedRoute>
                <MainLayout>
                  <Alerts />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/threats" element={
              <ProtectedRoute>
                <MainLayout>
                  <Threats />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/threats/cve" element={
              <ProtectedRoute>
                <MainLayout>
                  <ThreatCve />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/threats/intel" element={
              <ProtectedRoute>
                <MainLayout>
                  <ThreatIntel />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/threats/mitre" element={
              <ProtectedRoute>
                <MainLayout>
                  <ThreatMitre />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/threats/osint" element={
              <ProtectedRoute>
                <MainLayout>
                  <ThreatOsint />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/network" element={
              <ProtectedRoute>
                <MainLayout>
                  <Network />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/logs" element={
              <ProtectedRoute>
                <MainLayout>
                  <Logs />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/models" element={
              <ProtectedRoute>
                <MainLayout>
                  <Models />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/users" element={
              <ProtectedRoute>
                <MainLayout>
                  <Users />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/settings" element={
              <ProtectedRoute>
                <MainLayout>
                  <Settings />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            <Route path="/attack-simulations" element={
              <ProtectedRoute>
                <MainLayout>
                  <AttackSimulations />
                </MainLayout>
              </ProtectedRoute>
            } />
            
            {/* Catch all route */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
        
        {/* Global modals */}
        <Suspense fallback={null}>
          <AuthModal />
        </Suspense>
      </div>
    </ErrorBoundary>
  );
};

export default App;

