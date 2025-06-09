import React, { forwardRef } from 'react'; // Import forwardRef
import { Send, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface ChatInputProps {
  input: string;
  isTyping: boolean;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onSend: () => void;
}

const ChatInput = forwardRef<HTMLInputElement, ChatInputProps>(({
  input,
  isTyping,
  onInputChange,
  onSend
}, ref) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isTyping && input.trim()) {
      onSend();
    }
  };

  return (
    <div className="p-4 border-t border-border">
      <form
        className="flex items-center space-x-2"
        onSubmit={handleSubmit}
      >
        <label htmlFor="chat-input" className="sr-only">Type your message</label>
        <Input
          ref={ref} // Apply the forwarded ref here
          id="chat-input"
          placeholder="Ask about security events, alerts, or data..."
          value={input}
          onChange={onInputChange}
          className="flex-1"
          disabled={isTyping}
        />
        <Button type="submit" size="icon" disabled={isTyping} aria-label={isTyping ? "Sending..." : "Send message"}>
          {isTyping ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send size={16} />}
        </Button>
      </form>
    </div>
  );
});

export default ChatInput;
