
import React, { useRef } from 'react';
import { ArrowDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Message } from './types';
import MessageItem from './MessageItem';

interface MessageListProps {
  messages: Message[];
  showScrollButton: boolean;
  getCategoryIcon: (category?: Message['category']) => React.ReactNode;
  onLikeMessage: (id: number) => void;
  onDeleteMessage: (id: number) => void;
  onScroll: () => void;
  scrollToBottom: () => void;
}

const MessageList: React.FC<MessageListProps> = ({
  messages,
  showScrollButton,
  getCategoryIcon,
  onLikeMessage,
  onDeleteMessage,
  onScroll,
  scrollToBottom
}) => {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  return (
    <div className="relative flex-1">
      <ScrollArea 
        className="flex-1 p-4 space-y-4 h-full" 
        onScroll={onScroll}
    aria-live="polite" // Added for screen readers
      >
        <div 
          ref={scrollAreaRef} 
          className="space-y-4"
          onScroll={onScroll}
        >
          {messages.map((message) => (
            <MessageItem 
              key={message.id}
              message={message}
              getCategoryIcon={getCategoryIcon}
              onLike={onLikeMessage}
              onDelete={onDeleteMessage}
            />
          ))}
          <div ref={messagesEndRef} />
        </div>
      </ScrollArea>
      
      {/* Scroll to bottom button */}
      {showScrollButton && (
        <Button
          className="absolute bottom-4 right-6 rounded-full h-8 w-8 p-0 bg-isimbi-purple hover:bg-isimbi-purple/90 shadow-lg"
          onClick={scrollToBottom}
      aria-label="Scroll to bottom"
        >
          <ArrowDown size={16} />
        </Button>
      )}
    </div>
  );
};

export default MessageList;
