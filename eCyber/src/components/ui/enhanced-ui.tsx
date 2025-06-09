// Enhanced UI components for better UX
import React from 'react';
import { AlertCircle, CheckCircle, Info, XCircle, Loader2, Wifi, WifiOff } from 'lucide-react';
import { cn } from '@/lib/utils';

// Enhanced Loading Spinner
interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  message?: string;
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 'md', 
  message,
  className 
}) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12'
  };

  return (
    <div className={cn('flex flex-col items-center justify-center space-y-2', className)}>
      <Loader2 className={cn('animate-spin text-primary', sizeClasses[size])} />
      {message && (
        <p className="text-sm text-muted-foreground animate-pulse">{message}</p>
      )}
    </div>
  );
};

// Enhanced Alert Component
interface AlertProps {
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  onClose?: () => void;
  className?: string;
}

export const Alert: React.FC<AlertProps> = ({ 
  type, 
  title, 
  message, 
  onClose,
  className 
}) => {
  const icons = {
    success: CheckCircle,
    error: XCircle,
    warning: AlertCircle,
    info: Info
  };

  const styles = {
    success: 'bg-green-50 border-green-200 text-green-800',
    error: 'bg-red-50 border-red-200 text-red-800',
    warning: 'bg-yellow-50 border-yellow-200 text-yellow-800',
    info: 'bg-blue-50 border-blue-200 text-blue-800'
  };

  const Icon = icons[type];

  return (
    <div className={cn(
      'border rounded-lg p-4 flex items-start space-x-3',
      styles[type],
      className
    )}>
      <Icon className="h-5 w-5 mt-0.5 flex-shrink-0" />
      <div className="flex-1">
        {title && <h4 className="font-medium mb-1">{title}</h4>}
        <p className="text-sm">{message}</p>
      </div>
      {onClose && (
        <button
          onClick={onClose}
          className="text-current hover:opacity-70 transition-opacity"
        >
          <XCircle className="h-4 w-4" />
        </button>
      )}
    </div>
  );
};

// Connection Status Indicator
interface ConnectionStatusProps {
  isConnected: boolean;
  message?: string;
  className?: string;
}

export const ConnectionStatus: React.FC<ConnectionStatusProps> = ({ 
  isConnected, 
  message,
  className 
}) => {
  return (
    <div className={cn(
      'flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium',
      isConnected 
        ? 'bg-green-100 text-green-800' 
        : 'bg-red-100 text-red-800',
      className
    )}>
      {isConnected ? (
        <Wifi className="h-3 w-3" />
      ) : (
        <WifiOff className="h-3 w-3" />
      )}
      <span>
        {message || (isConnected ? 'Connected' : 'Disconnected')}
      </span>
    </div>
  );
};

// Empty State Component
interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className
}) => {
  return (
    <div className={cn(
      'flex flex-col items-center justify-center text-center p-8 space-y-4',
      className
    )}>
      {icon && (
        <div className="text-muted-foreground">
          {icon}
        </div>
      )}
      <div className="space-y-2">
        <h3 className="text-lg font-medium text-foreground">{title}</h3>
        {description && (
          <p className="text-sm text-muted-foreground max-w-md">{description}</p>
        )}
      </div>
      {action && action}
    </div>
  );
};

// Skeleton Loader
interface SkeletonProps {
  className?: string;
  lines?: number;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className, lines = 1 }) => {
  return (
    <div className="space-y-2">
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={cn(
            'animate-pulse bg-muted rounded h-4',
            className
          )}
        />
      ))}
    </div>
  );
};

// Card Skeleton
export const CardSkeleton: React.FC = () => {
  return (
    <div className="border rounded-lg p-6 space-y-4">
      <Skeleton className="h-6 w-1/3" />
      <Skeleton lines={3} />
      <div className="flex space-x-2">
        <Skeleton className="h-8 w-20" />
        <Skeleton className="h-8 w-20" />
      </div>
    </div>
  );
};

// Table Skeleton
export const TableSkeleton: React.FC<{ rows?: number; columns?: number }> = ({ 
  rows = 5, 
  columns = 4 
}) => {
  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex space-x-4">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex space-x-4">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
};

// Progress Bar
interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  showPercentage?: boolean;
  className?: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  label,
  showPercentage = true,
  className
}) => {
  const percentage = Math.min((value / max) * 100, 100);

  return (
    <div className={cn('space-y-2', className)}>
      {(label || showPercentage) && (
        <div className="flex justify-between text-sm">
          {label && <span className="text-foreground">{label}</span>}
          {showPercentage && (
            <span className="text-muted-foreground">{percentage.toFixed(1)}%</span>
          )}
        </div>
      )}
      <div className="w-full bg-muted rounded-full h-2">
        <div
          className="bg-primary h-2 rounded-full transition-all duration-300 ease-in-out"
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
};

// Status Badge
interface StatusBadgeProps {
  status: 'online' | 'offline' | 'warning' | 'error';
  label?: string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ 
  status, 
  label,
  className 
}) => {
  const styles = {
    online: 'bg-green-100 text-green-800 border-green-200',
    offline: 'bg-gray-100 text-gray-800 border-gray-200',
    warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    error: 'bg-red-100 text-red-800 border-red-200'
  };

  const dots = {
    online: 'bg-green-400',
    offline: 'bg-gray-400',
    warning: 'bg-yellow-400',
    error: 'bg-red-400'
  };

  return (
    <span className={cn(
      'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
      styles[status],
      className
    )}>
      <div className={cn('w-2 h-2 rounded-full mr-1.5', dots[status])} />
      {label || status}
    </span>
  );
};

// Metric Card
interface MetricCardProps {
  title: string;
  value: string | number;
  change?: {
    value: number;
    type: 'increase' | 'decrease';
  };
  icon?: React.ReactNode;
  className?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  change,
  icon,
  className
}) => {
  return (
    <div className={cn(
      'bg-card border rounded-lg p-6 space-y-2',
      className
    )}>
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-muted-foreground">{title}</p>
        {icon && <div className="text-muted-foreground">{icon}</div>}
      </div>
      <div className="space-y-1">
        <p className="text-2xl font-bold text-foreground">{value}</p>
        {change && (
          <p className={cn(
            'text-xs font-medium',
            change.type === 'increase' ? 'text-green-600' : 'text-red-600'
          )}>
            {change.type === 'increase' ? '+' : '-'}{Math.abs(change.value)}%
          </p>
        )}
      </div>
    </div>
  );
};

// Error Fallback Component
interface ErrorFallbackProps {
  error: Error;
  resetError: () => void;
}

export const ErrorFallback: React.FC<ErrorFallbackProps> = ({ error, resetError }) => {
  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
      <XCircle className="h-12 w-12 text-red-500" />
      <div className="text-center space-y-2">
        <h2 className="text-lg font-semibold text-foreground">Something went wrong</h2>
        <p className="text-sm text-muted-foreground max-w-md">
          {error.message || 'An unexpected error occurred'}
        </p>
      </div>
      <button
        onClick={resetError}
        className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
      >
        Try again
      </button>
    </div>
  );
};

