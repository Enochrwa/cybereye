import { describe, it, expect, vi } from 'vitest'; // Or 'jest'
import { generateAIResponse, KnowledgeBaseItem } from './utils';
import knowledgeBaseData from './knowledgeBase.json';

// Mock the jaro-winkler module
vi.mock('jaro-winkler', () => ({
  default: (str1: string, str2: string) => {
    // Simple mock: perfect match = 1, else 0.5, or specific values for tests
    if (str1 === str2) return 1.0;
    if ((str1 === 'firewal' && str2 === 'firewall') || (str1 === 'firewall' && str2 === 'firewal')) return 0.9; // Simulate fuzzy
    // Add more specific mocks if needed for more nuanced fuzzy tests
    let score = 0;
    const minLen = Math.min(str1.length, str2.length);
    for(let i = 0; i < minLen; i++) {
        if(str1[i] === str2[i]) score++;
    }
    return score / Math.max(str1.length, str2.length);
  }
}));

// Mock knowledgeBase.json - use a subset for easier testing
const mockKnowledgeBase: KnowledgeBaseItem[] = [
  {
    id: 'firewall',
    name: 'Firewall Management',
    keywords: ['firewall', 'network rules', 'traffic filtering', 'port blocking'],
    description: 'Firewalls are used to control incoming and outgoing network traffic.',
    components: [{ name: 'Firewall Service', type: 'Service', description: 'Manages firewall rules' }],
  },
  {
    id: 'threat_intel',
    name: 'Threat Intelligence',
    keywords: ['threat intelligence', 'ioc', 'malware signatures', 'attack patterns'],
    description: 'Threat intelligence provides information about current and potential threats.',
    components: [],
  },
  {
    id: 'dashboard',
    name: 'System Dashboard',
    keywords: ['dashboard', 'overview', 'system status', 'metrics'],
    description: 'The main dashboard shows an overview of the system status.',
    components: [],
  }
];

// Temporarily override the imported knowledgeBaseData in utils.ts for testing
// This is a bit of a hack. In a real setup, you might inject dependencies or use more advanced mocking.
vi.mock('./knowledgeBase.json', () => ({
  default: mockKnowledgeBase
}));


describe('generateAIResponse', () => {
  it('should return a specific response for an exact keyword match', () => {
    const userInput = 'Tell me about firewall';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('firewall');
    expect(response.responseText).toContain('**Firewall Management**');
    expect(response.responseText).toContain('Firewalls are used to control incoming and outgoing network traffic.');
    expect(response.tags).toEqual(['firewall', 'network rules', 'traffic filtering', 'port blocking']);
  });

  it('should return a specific response for a query with multiple keywords from one item', () => {
    const userInput = 'dashboard system status';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('dashboard');
    expect(response.responseText).toContain('**System Dashboard**');
  });
  
  it('should handle slightly misspelled keywords using fuzzy matching (mocked)', () => {
    // Mock jaroWinkler to return a high score for "firewal" vs "firewall"
    // This is handled by the top-level mock, ensuring 'firewal' matches 'firewall'
    const userInput = 'What is a firewal?';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('firewall');
    expect(response.responseText).toContain('**Firewall Management**');
  });

  it('should return the default fallback response for queries with no relevant keywords', () => {
    const userInput = 'What is the weather like today?';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('unknown');
    expect(response.responseText).toContain("I'm sorry, I couldn't find specific information");
  });

  it('should return a fallback response if fuzzy match score is too low', () => {
    // Assuming 'qwertyuiop' will have a very low score against any keyword
    const userInput = 'qwertyuiop';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('unknown');
    expect(response.responseText).toContain("I'm sorry, I couldn't find specific information");
  });

  it('should prioritize items with more matched keywords or better overall scores', () => {
    // This test depends heavily on the scoring logic and mockKnowledgeBase structure.
    // "threat intelligence overview" - 'threat intelligence' is a strong match for threat_intel.
    // 'overview' matches 'dashboard'.
    // The refined scoring should prefer 'threat_intel' if its keywords score higher or provide better coverage.
    const userInput = 'threat intelligence overview';
    const response = generateAIResponse(userInput);
    // This expectation might need adjustment based on how the scoring weights are tuned.
    // For this example, let's assume "threat intelligence" is a more unique/stronger signal.
    expect(response.category).toBe('threat_intel'); 
    expect(response.responseText).toContain('**Threat Intelligence**');
  });

  it('should include component descriptions if present', () => {
    const userInput = 'firewall components';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('firewall');
    expect(response.responseText).toContain('**Related Components:**');
    expect(response.responseText).toContain('- **Firewall Service (Service):** Manages firewall rules');
  });

  it('should handle empty user input gracefully', () => {
    const userInput = '';
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('unknown');
    expect(response.responseText).toContain("I'm sorry, I couldn't find specific information");
  });

  it('should handle user input with only very short words', () => {
    const userInput = 'a an the of'; // These are filtered out by length check
    const response = generateAIResponse(userInput);
    expect(response.category).toBe('unknown');
    expect(response.responseText).toContain("I'm sorry, I couldn't find specific information");
  });
});
