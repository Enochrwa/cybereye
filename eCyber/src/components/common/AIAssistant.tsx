
import React, { useState, useEffect, useRef } from 'react';
import { Bot, X, Maximize2, Minimize2, Info, AlertTriangle, Network, Cpu, User, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useTheme } from '@/components/theme/ThemeProvider';
import { useToast } from "@/hooks/use-toast";
import { Message } from './ai-assistant/types';
import { initialMessages } from './ai-assistant/constants';
// import { generateAIResponse } from './ai-assistant/utils'; // Will be replaced
import knowledgeBase from './ai-assistant/KnowledgeBase.json'
import MessageList from './ai-assistant/MessageList';
import ChatInput from './ai-assistant/ChatInput';
import SuggestedQuestions from './ai-assistant/SuggestedQuestions';
import InfoTab from './ai-assistant/InfoTab';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

interface AIAssistantProps {
  className?: string;
}

const AIAssistant: React.FC<AIAssistantProps> = ({ className }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState('chat');
  const [messages, setMessages] = useState<Message[]>(initialMessages);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null); // Ref for the chat input
  const { theme } = useTheme();
  const { toast } = useToast();

  // Define a type for the knowledge base items (optional, but good practice)
  interface KnowledgeBaseItem {
    id: string;
    name: string;
    keywords: string[];
    description: string;
    components: Array<{ name: string; type: string; description: string }>;
    dataFlow?: string;
    configuration?: string;
    troubleshooting?: string;
    relatedTopics?: string[];
  }

  const generateAIResponse = (userInput: string): { responseText: string; category?: string; tags?: string[] } => {
    const inputKeywords = userInput.toLowerCase().split(/\s+/);
    let bestMatch: KnowledgeBaseItem | null = null;
    let maxMatchCount = 0;

    knowledgeBase.forEach((item: KnowledgeBaseItem) => {
      const currentMatchCount = item.keywords.filter(kw => inputKeywords.includes(kw.toLowerCase())).length;
      if (currentMatchCount > maxMatchCount) {
        maxMatchCount = currentMatchCount;
        bestMatch = item;
      }
    });

    if (bestMatch) {
      let response = `**${bestMatch.name}**

${bestMatch.description}

`;
      
      if (bestMatch.components && bestMatch.components.length > 0) {
        response += "**Related Components:**\n";
        bestMatch.components.forEach(comp => {
          response += `- **${comp.name} (${comp.type}):** ${comp.description}\n`;
        });
        response += "\n";
      }

      if (bestMatch.dataFlow) {
        response += `**Data Flow:**
${bestMatch.dataFlow}

`;
      }

      if (bestMatch.configuration) {
        response += `**Configuration:**
${bestMatch.configuration}

`;
      }

      if (bestMatch.troubleshooting) {
        response += `**Troubleshooting:**
${bestMatch.troubleshooting}

`;
      }
      
      // Remove trailing newlines
      response = response.trim();

      return {
        responseText: response,
        category: bestMatch.id, // Use the id as category
        tags: bestMatch.keywords,
      };
    }

    return {
      responseText: "I'm sorry, I couldn't find specific information related to your query. Could you try rephrasing or asking about a different topic?",
      category: 'unknown',
      tags: [],
    };
  };

  // Function to scroll to the bottom of the messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  // Function to handle scroll events in the message area
  const handleScroll = () => {
    const scrollElement = document.querySelector('.scroll-area-viewport');
    if (!scrollElement) return;
    
    const { scrollTop, scrollHeight, clientHeight } = scrollElement;
    // Show scroll button when not at bottom
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
    setShowScrollButton(!isAtBottom);
  };

  // Auto-scroll on new messages
  useEffect(() => {
    if (isOpen && !showScrollButton) {
    // Focus input when panel opens or becomes active, and not showing suggestions
    if (activeTab === 'chat' && !showSuggestions && inputRef.current) {
      inputRef.current.focus();
    }
      scrollToBottom();
    }
  }, [messages, isOpen, showScrollButton, activeTab, showSuggestions]);

  // Effect to focus input when panel is opened and tab is chat
  useEffect(() => {
    if (isOpen && activeTab === 'chat' && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100); // Timeout to ensure element is visible
    }
  }, [isOpen, activeTab]);

  // Function to handle sending a new message
  const handleSendMessage = () => {
    if (!input.trim()) return;

    // Add user message
    const userMessage: Message = {
      id: messages.length + 1,
      text: input,
      sender: 'user',
      timestamp: new Date(),
    };
    
    setMessages([...messages, userMessage]);
    setInput('');
    setIsTyping(true);
    setShowSuggestions(false);

    // Auto-scroll when sending a message
    setShowScrollButton(false);
    
    // Simulate AI thinking
    setTimeout(() => {
      const aiMessage: Message = {
        id: messages.length + 2,
        text: '',
        sender: 'ai',
        timestamp: new Date(),
        isTyping: true,
      };
      
      setMessages(prevMessages => [...prevMessages, aiMessage]);

      // Simulate AI response with typing effect
      setTimeout(() => {
        const { responseText, category, tags } = generateAIResponse(input);
        
        setMessages(prevMessages => 
          prevMessages.map(msg => 
            msg.id === prevMessages[prevMessages.length - 1].id
              ? { 
                  ...msg, 
                  text: responseText, 
                  isTyping: false,
                  category,
                  tags
                }
              : msg
          )
        );
        
        setIsTyping(false);
      }, 1500);
    }, 500);
  };

  // Function to like a message
  const handleLikeMessage = (id: number) => {
    setMessages(prevMessages => 
      prevMessages.map(msg => 
        msg.id === id
          ? { ...msg, liked: !msg.liked }
          : msg
      )
    );
    
    toast({
      title: "Message reaction updated",
      description: "Your feedback has been recorded.",
      duration: 2000,
    });
  };

  // Function to delete a message and its response
  const handleDeleteMessage = (id: number) => {
    // Find the message
    const messageIndex = messages.findIndex(msg => msg.id === id);
    if (messageIndex === -1) return;
    
    const message = messages[messageIndex];
    let messagesToDelete = [id];
    
    // If this is a user message, also delete the next AI response
    if (message.sender === 'user' && messageIndex + 1 < messages.length) {
      const nextMessage = messages[messageIndex + 1];
      if (nextMessage.sender === 'ai') {
        messagesToDelete.push(nextMessage.id);
      }
    }
    // If this is an AI message, also delete the previous user message
    else if (message.sender === 'ai' && messageIndex > 0) {
      const prevMessage = messages[messageIndex - 1];
      if (prevMessage.sender === 'user') {
        messagesToDelete.push(prevMessage.id);
      }
    }
    
    setMessages(prevMessages => 
      prevMessages.filter(msg => !messagesToDelete.includes(msg.id))
    );
    
    toast({
      title: "Message deleted",
      description: "The selected message has been removed.",
      duration: 2000,
    });
  };

  // Handle suggestion click
  const handleSuggestionClick = (suggestion: string) => {
    setInput(suggestion);
    setShowSuggestions(false);
  };

  // Get the appropriate icon for a message category
  const getCategoryIcon = (category?: Message['category']) => {
    switch(category) {
      case 'threat': return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'network': return <Network className="h-4 w-4 text-blue-400" />;
      case 'model': return <Cpu className="h-4 w-4 text-purple-400" />;
      case 'user': return <User className="h-4 w-4 text-green-400" />;
      case 'system': return <Settings className="h-4 w-4 text-amber-400" />;
      default: return <Bot className="h-4 w-4 text-isimbi-purple" />;
    }
  };

  // Clear chat history
  const clearChat = () => {
    setMessages(initialMessages);
    setShowSuggestions(true);
    toast({
      title: "Chat history cleared",
      description: "All messages have been cleared.",
      duration: 2000,
    });
  };

  return (
    <>
      {/* Chat button */}
      {!isOpen && (
        <Button 
          onClick={() => setIsOpen(true)}
          className="fixed bottom-20 right-6 h-14 w-14 rounded-full shadow-lg bg-blue-700 hover:bg-blue-600 flex items-center justify-center"
          aria-label="Open AI Assistant"
        >
          <Bot size={24} />
        </Button>
      )}
      
      {/* Chat panel */}
      {isOpen && (
        <div 
          className={cn(
            "fixed bottom-20 right-6 glass-card border border-white/10 shadow-xl flex flex-col",
            "transition-all duration-300 z-50",
            isExpanded ? "w-[80vw] h-[80vh] max-w-4xl translate-x-0" : "w-96 h-[500px] max-w-[90vw]",
            theme === 'dark' ? 'bg-background/90 backdrop-blur-md' : 'bg-white/95 backdrop-blur-md',
            className
          )}
        >
          {/* Header */}
          <div className="p-4 border-b border-border flex items-center justify-between">
            <div className="flex items-center">
              <div className="h-8 w-8 rounded-full bg-blue-700/30 flex items-center justify-center mr-2">
                <Bot className="h-5 w-5 text-blue-300" />
              </div>
              <div>
                <h3 className="font-medium">eCyber AIAssistant</h3>
                <p className="text-xs text-muted-foreground">Expert security guidance</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    className="h-8 w-8 p-0" 
                    onClick={() => setActiveTab(activeTab === 'chat' ? 'info' : 'chat')}
                    aria-label={activeTab === 'chat' ? "Show info tab" : "Show chat tab"}
                  >
                    <Info size={16} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p>About this assistant</p>
                </TooltipContent>
              </Tooltip>
              
              <Button 
                variant="ghost" 
                size="sm" 
                className="h-8 w-8 p-0" 
                onClick={() => setIsExpanded(!isExpanded)}
                aria-label={isExpanded ? "Collapse assistant" : "Expand assistant"}
              >
                {isExpanded ? <Maximize2 size={16} /> : <Maximize2 size={16} />}
              </Button>
              
              <Button 
                variant="ghost" 
                size="sm" 
                className="h-8 w-8 p-0" 
                onClick={() => setIsOpen(false)}
                aria-label="Close assistant"
              >
                <X size={16} />
              </Button>
            </div>
          </div>
          
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col">
            {/* Main chat tab */}
            <TabsContent value="chat" className="flex-1 flex flex-col data-[state=active]:flex-1 h-0">
              <MessageList 
                messages={messages}
                showScrollButton={showScrollButton}
                getCategoryIcon={getCategoryIcon}
                onLikeMessage={handleLikeMessage}
                onDeleteMessage={handleDeleteMessage}
                onScroll={handleScroll}
                scrollToBottom={scrollToBottom}
              />
              
              {/* Suggested questions */}
              {showSuggestions && (
                <SuggestedQuestions onSuggestionClick={handleSuggestionClick} />
              )}
              
              {/* Input */}
              <ChatInput 
                input={input}
                isTyping={isTyping}
                onInputChange={(e) => setInput(e.target.value)}
                // Pass the ref to ChatInput, ChatInput needs to accept and forward this ref to its Input component
                onSend={handleSendMessage}
                ref={inputRef}
              />
            </TabsContent>
            
            {/* Info tab */}
            <TabsContent value="info">
              <InfoTab clearChat={clearChat} />
            </TabsContent>
          </Tabs>
        </div>
      )}
    </>
  );
};

export default AIAssistant;
