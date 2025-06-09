
import React from 'react';
import { cn } from '@/lib/utils';
import { TypingIndicatorProps } from './types';

const TypingIndicator: React.FC<TypingIndicatorProps> = ({ className }) => {
  return (
    <div className={cn("flex items-center space-x-1", className)}>
      <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
      <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
      <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: "600ms" }} />
    </div>
  );
};

export default TypingIndicator;
