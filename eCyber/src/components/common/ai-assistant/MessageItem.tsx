
import React from 'react';
import { ThumbsUp, Trash2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Message } from './types';
import TypingIndicator from './TypingIndicator';
import { getTimeDisplay } from './utils';

interface MessageItemProps {
  message: Message;
  getCategoryIcon: (category?: Message['category']) => React.ReactNode;
  onLike: (id: number) => void;
  onDelete: (id: number) => void;
}

const MessageItem: React.FC<MessageItemProps> = ({ 
  message, 
  getCategoryIcon, 
  onLike, 
  onDelete 
}) => {
  return (
    <div 
      className={cn(
        "max-w-[80%] rounded-xl p-3 relative group", // Changed to rounded-xl
        message.sender === 'user' 
          ? "bg-isimbi-purple/20 ml-auto" 
          : "bg-secondary/50"
      )}
    >
      {message.sender === 'ai' && (
        <div className="flex items-center space-x-2 mb-1">
          {getCategoryIcon(message.category)}
          <span className="text-xs font-medium">ISIMBI Assistant</span>
          {message.category && (
            <Badge variant="outline" className="text-xs">
              {message.category.charAt(0).toUpperCase() + message.category.slice(1)}
            </Badge>
          )}
        </div>
      )}
      
      <div className="text-sm">
        {message.isTyping ? (
          <TypingIndicator className="text-muted-foreground" />
        ) : (
          message.text
        )}
      </div>
      
      <div className="flex items-center justify-between mt-1">
        <div className="text-xs text-muted-foreground flex items-center space-x-2">
          <span>{getTimeDisplay(message.timestamp)}</span>
          <div className="opacity-0 group-hover:opacity-100 transition-opacity">
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0 hover:bg-transparent"
              onClick={() => onLike(message.id)}
              aria-label={message.liked ? "Unlike message" : "Like message"}
            >
              <ThumbsUp 
                size={14} 
                className={cn(message.liked ? "text-isimbi-purple fill-isimbi-purple" : "")}
              />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0 hover:bg-transparent hover:text-destructive"
              onClick={() => onDelete(message.id)}
              aria-label="Delete message"
            >
              <Trash2 size={14} />
            </Button>
          </div>
        </div>
        
        {message.tags && message.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 justify-end">
            {message.tags.map((tag, i) => (
              <Badge key={i} variant="secondary" className="text-[10px]">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default MessageItem;
