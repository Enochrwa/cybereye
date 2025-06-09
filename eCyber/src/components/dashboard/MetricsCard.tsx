
import React from 'react';
import { cn } from '@/lib/utils';
import { cva } from 'class-variance-authority';

const cardVariants = cva(
  "glass-card p-5 flex flex-col transition-all duration-300 hover:shadow-xl group relative overflow-hidden",
  {
    variants: {
      variant: {
        default: "",
        alert: "border-l-4 border-l-destructive",
        success: "border-l-4 border-l-green-500",
        warning: "border-l-4 border-l-amber-500",
        info: "border-l-4 border-l-isimbi-bright-blue",
      },
      size: {
        default: "",
        sm: "p-4",
        lg: "p-6",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

type TrendDirection = 'up' | 'down' | 'neutral';

interface MetricsCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon?: React.ReactNode;
  trend?: {
    direction: TrendDirection;
    value: string;
    label?: string;
  };
  variant?: "default" | "alert" | "success" | "warning" | "info";
  size?: "default" | "sm" | "lg";
  loading?: boolean;
  className?: string;
  onClick?: () => void;
}

const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  description,
  icon,
  trend,
  variant = "default",
  size = "default",
  loading = false,
  className,
  onClick,
}) => {
  return (
    <div 
      className={cn(cardVariants({ variant, size }), 
      "cursor-pointer hover:translate-y-[-2px]", 
      className)}
      onClick={onClick}
    >
      {/* Background decorative element */}
      <div 
        className="absolute -right-4 -top-4 w-24 h-24 bg-isimbi-purple/10 rounded-full 
                  blur-2xl opacity-50 transition-all group-hover:opacity-75"
      ></div>
      
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
        {icon && <div className="text-muted-foreground">{icon}</div>}
      </div>
      
      {/* Main Value */}
      {loading ? (
        <div className="h-8 bg-secondary/30 rounded animate-pulse mb-2"></div>
      ) : (
        <div className="text-2xl font-bold mb-1 data-highlight">{value}</div>
      )}
      
      {/* Description */}
      {description && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
      
      {/* Trend */}
      {trend && (
        <div className="flex items-center space-x-1 mt-3">
          {trend.direction === 'up' && (
            <span className="text-green-500">↑</span>
          )}
          {trend.direction === 'down' && (
            <span className="text-red-500">↓</span>
          )}
          <span className={cn(
            "text-xs font-medium",
            trend.direction === 'up' && "text-green-500",
            trend.direction === 'down' && "text-red-500",
            trend.direction === 'neutral' && "text-muted-foreground",
          )}>
            {trend.value}
          </span>
          {trend.label && (
            <span className="text-xs text-muted-foreground">{trend.label}</span>
          )}
        </div>
      )}
    </div>
  );
};

export default MetricsCard;
