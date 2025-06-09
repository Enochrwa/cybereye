
import React from 'react';
import { FileText, AlertTriangle, Database, Server } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SECURITY_TOPICS, initialMessages } from './constants'; // Import initialMessages
import { Message } from './types'; // Import Message type

interface InfoTabProps {
  clearChat: () => void;
  showSuggestions: boolean;
  setShowSuggestions: (show: boolean) => void;
  messages: Message[];
}

const InfoTab: React.FC<InfoTabProps> = ({ clearChat, showSuggestions, setShowSuggestions, messages }) => {
  // const canShowSuggestions = !showSuggestions && messages.length > initialMessages.length; // Not directly used, but logic is in disabled state
  const initialMessagesLength = initialMessages.length;

  return (
    <div className="p-4 space-y-4 data-[state=active]:flex-1 h-0 overflow-auto">
      <div>
        <h3 className="font-medium mb-2">About ISIMBI AI Assistant</h3>
        <p className="text-sm text-muted-foreground">
          The ISIMBI AI Assistant helps you navigate and utilize the comprehensive security monitoring platform. 
          It provides expert guidance on threat intelligence, network security, AI models, and user management.
        </p>
      </div>
      
      <div>
        <h4 className="font-medium mb-2 text-sm">Available Topics</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {SECURITY_TOPICS.map((topic) => (
            <div key={topic.id} className="p-3 border border-border rounded-md">
              <div className="flex items-center mb-1">
                <topic.icon className="h-4 w-4 mr-2 text-isimbi-purple" />
                <span className="font-medium text-sm">{topic.title}</span>
              </div>
              <p className="text-xs text-muted-foreground">{topic.description}</p>
            </div>
          ))}
        </div>
      </div>
      
      <div>
        <h4 className="font-medium mb-2 text-sm">Capabilities</h4>
        <ul className="space-y-2">
          <li className="text-sm flex items-start">
            <FileText className="h-4 w-4 mr-2 mt-0.5 text-isimbi-purple" />
            <span>Explain security concepts and platform features</span>
          </li>
          <li className="text-sm flex items-start">
            <AlertTriangle className="h-4 w-4 mr-2 mt-0.5 text-isimbi-purple" />
            <span>Provide information about threat intelligence</span>
          </li>
          <li className="text-sm flex items-start">
            <Database className="h-4 w-4 mr-2 mt-0.5 text-isimbi-purple" />
            <span>Help with data analysis and interpretation</span>
          </li>
          <li className="text-sm flex items-start">
            <Server className="h-4 w-4 mr-2 mt-0.5 text-isimbi-purple" />
            <span>Guide you through system configuration</span>
          </li>
        </ul>
      </div>
      
      <div className="pt-2 space-y-2">
        <Button variant="outline" size="sm" onClick={clearChat} className="w-full sm:w-auto">
          Clear conversation history
        </Button>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={() => setShowSuggestions(true)}
          disabled={showSuggestions || messages.length <= initialMessagesLength}
          className="w-full sm:w-auto"
        >
          Show Suggested Questions
        </Button>
        <div className="mt-4 text-xs text-muted-foreground">
          Platform version: 1.4.2 | AI Assistant version: 2.1.0
        </div>
      </div>
    </div>
  );
};

export default InfoTab;
