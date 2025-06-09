
import { AlertTriangle, Network, Database, User, Cpu, FileText, Server } from 'lucide-react';
import { SecurityTopic } from './types';

export const SECURITY_TOPICS: SecurityTopic[] = [
  { 
    id: 'threat-intel',
    title: 'Threat Intelligence',
    description: 'Information about emerging threats, malware variants, and attack patterns',
    icon: AlertTriangle
  },
  { 
    id: 'network-security',
    title: 'Network Security',
    description: 'Network monitoring, traffic analysis, and intrusion detection',
    icon: Network
  },
  { 
    id: 'system-security',
    title: 'System Security',
    description: 'Host protection, vulnerability management, and access control',
    icon: Server
  },
  { 
    id: 'data-protection',
    title: 'Data Protection',
    description: 'Encryption, data loss prevention, and sensitive information handling',
    icon: Database
  },
  { 
    id: 'user-security',
    title: 'User Security',
    description: 'Authentication, authorization, and identity management',
    icon: User
  },
  { 
    id: 'ai-models',
    title: 'AI Models',
    description: 'Security machine learning models, training, and analytics',
    icon: Cpu
  }
];

export const SUGGESTED_QUESTIONS = [
  "Explain how the threat feed integration works",
  "What security models are available in the system?",
  "How do I analyze network anomalies?",
  "Explain the user access control system",
  "What security metrics should I focus on?",
  "How does ISIMBI detect zero-day threats?"
];

export const initialMessages = [
  {
    id: 1,
    text: "Welcome to ISIMBI Security Platform! I'm your AI Assistant, designed to help you navigate and utilize our comprehensive security monitoring system. How can I assist you today?",
    sender: 'ai' as const,
    timestamp: new Date(),
    category: 'general' as const,
  }
];
