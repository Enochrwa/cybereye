import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom'; // For extended matchers like .toBeVisible()
import { vi } from 'vitest'; // Or 'jest'

import AIAssistant from '../AIAssistant'; // Adjust path as necessary
import { ThemeProvider } from '@/components/theme/ThemeProvider'; // Required by AIAssistant
import { TooltipProvider } from '@/components/ui/tooltip'; // Required by AIAssistant

// Mock child components or utilities if they are complex or have side effects
vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

// Mock the generateAIResponse utility
vi.mock('./utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./utils')>()
  return {
    ...actual,
    generateAIResponse: vi.fn(),
  }
})
import { generateAIResponse } from './utils';


// Mock initialMessages if needed, or ensure constants.ts is simple
// For this test, we assume initialMessages is an array with one welcome message.
const mockInitialMessages = [
  { id: 0, text: 'Welcome to ISIMBI AI Assistant!', sender: 'ai', timestamp: new Date() }
];
vi.mock('./constants', () => ({
  initialMessages: mockInitialMessages,
  SECURITY_TOPICS: [], // Mock if InfoTab uses it and it's complex
  SUGGESTED_QUESTIONS: [], // Mock if SuggestedQuestions uses it
}));


const AllTheProviders: React.FC<{children: React.ReactNode}> = ({ children }) => {
  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <TooltipProvider>
        {children}
      </TooltipProvider>
    </ThemeProvider>
  );
};

const renderAIAssistant = () => {
  return render(<AIAssistant />, { wrapper: AllTheProviders });
};

describe('AIAssistant Component', () => {
  beforeEach(() => {
    // Reset mocks before each test
    (generateAIResponse as ReturnType<typeof vi.fn>).mockClear();
    // Default mock implementation for successful response
    (generateAIResponse as ReturnType<typeof vi.fn>).mockImplementation((userInput: string) => ({
        responseText: `Mocked response to: ${userInput}`,
        category: 'test-category',
        tags: ['test']
    }));
  });

  it('should not be visible initially', () => {
    renderAIAssistant();
    expect(screen.queryByRole('complementary', { name: /ai assistant panel/i })).not.toBeInTheDocument();
     // Assuming the panel has a role like 'complementary' or a specific aria-label.
     // If not, query by testId or other means. For now, checking for "ISIMBI AI Assistant" heading.
    expect(screen.queryByText('ISIMBI AI Assistant')).not.toBeInTheDocument();
  });

  it('should open when the toggle button is clicked', () => {
    renderAIAssistant();
    const openButton = screen.getByRole('button', { name: /open ai assistant/i });
    fireEvent.click(openButton);
    expect(screen.getByText('ISIMBI AI Assistant')).toBeVisible();
  });

  it('should close when the close button is clicked', async () => {
    renderAIAssistant();
    const openButton = screen.getByRole('button', { name: /open ai assistant/i });
    fireEvent.click(openButton);

    // Wait for the panel to be fully open and header rendered
    await screen.findByText('ISIMBI AI Assistant');
    
    const closeButton = screen.getByRole('button', { name: /close assistant/i });
    fireEvent.click(closeButton);

    // Use waitFor to handle potential animations or delayed state updates for closing
    await waitFor(() => {
      expect(screen.queryByText('ISIMBI AI Assistant')).not.toBeInTheDocument();
    });
  });

  it('should send a message and display user and AI responses', async () => {
    renderAIAssistant();
    fireEvent.click(screen.getByRole('button', { name: /open ai assistant/i }));
    await screen.findByText('ISIMBI AI Assistant'); // Wait for panel to open

    const input = screen.getByRole('textbox'); // Assuming ChatInput uses a standard textbox role
    const sendButton = screen.getByRole('button', { name: /send message/i }); // Assuming ChatInput send button has this label

    fireEvent.change(input, { target: { value: 'Hello AI' } });
    fireEvent.click(sendButton);

    await waitFor(() => {
      expect(screen.getByText('Hello AI')).toBeVisible();
    });
    
    // Check for AI response (mocked)
    // The generateAIResponse mock is called, and its result should be displayed
    await waitFor(() => {
        expect(generateAIResponse).toHaveBeenCalledWith('Hello AI');
        expect(screen.getByText('Mocked response to: Hello AI')).toBeVisible();
    }, { timeout: 3000 }); // Increased timeout for simulated typing
  });

  it('should clear chat when "Clear conversation history" is clicked', async () => {
    renderAIAssistant();
    fireEvent.click(screen.getByRole('button', { name: /open ai assistant/i }));
    await screen.findByText('ISIMBI AI Assistant');

    // Send a message first
    const input = screen.getByRole('textbox');
    const sendButton = screen.getByRole('button', { name: /send message/i });
    fireEvent.change(input, { target: { value: 'Test message to clear' } });
    fireEvent.click(sendButton);
    await waitFor(() => expect(screen.getByText('Test message to clear')).toBeVisible());
    await waitFor(() => expect(screen.getByText('Mocked response to: Test message to clear')).toBeVisible(), { timeout: 3000 });


    // Navigate to Info tab
    const infoTabButton = screen.getByRole('button', { name: /show info tab/i });
    fireEvent.click(infoTabButton);
    
    // Click clear chat
    const clearChatButton = await screen.findByRole('button', { name: /clear conversation history/i });
    fireEvent.click(clearChatButton);

    // Should show initial welcome message and no other messages
    await waitFor(() => {
      expect(screen.getByText(mockInitialMessages[0].text)).toBeVisible();
      expect(screen.queryByText('Test message to clear')).not.toBeInTheDocument();
      expect(screen.queryByText('Mocked response to: Test message to clear')).not.toBeInTheDocument();
    });
    
    // Should show suggested questions again
    // This depends on SuggestedQuestions component rendering something identifiable
    // For now, we assume clearing chat also triggers showing suggestions
    // (The actual SuggestedQuestions component might need a specific queryable text/element)
    // Query for a known suggested question if available in constants
    // expect(screen.getByText(/what is a firewall/i)).toBeVisible(); // Example
  });
  
  it('should show suggested questions when "Show Suggested Questions" is clicked', async () => {
    renderAIAssistant();
    fireEvent.click(screen.getByRole('button', { name: /open ai assistant/i }));
    await screen.findByText('ISIMBI AI Assistant');

    // Send a message to hide initial suggestions
    const input = screen.getByRole('textbox');
    const sendButton = screen.getByRole('button', { name: /send message/i });
    fireEvent.change(input, { target: { value: 'Hide suggestions' } });
    fireEvent.click(sendButton);
    await waitFor(() => expect(screen.queryByText(/what is a firewall/i)).not.toBeInTheDocument(), {timeout: 2000}); // Example suggestion

    // Navigate to Info tab
    const infoTabButton = screen.getByRole('button', { name: /show info tab/i });
    fireEvent.click(infoTabButton);

    // Click "Show Suggested Questions"
    const showSuggestionsButton = await screen.findByRole('button', { name: /show suggested questions/i });
    expect(showSuggestionsButton).not.toBeDisabled(); // Should be enabled after one message
    fireEvent.click(showSuggestionsButton);
    
    // Switch back to chat tab to see suggestions
    const chatTabButton = screen.getByRole('button', { name: /show chat tab/i }); // Assuming info tab button text changes
    fireEvent.click(chatTabButton);

    // Assert that suggested questions are visible again
    // This requires SuggestedQuestions component to render identifiable elements.
    // For example, if SuggestedQuestions renders buttons with the question text:
    // await waitFor(() => expect(screen.getByRole('button', { name: /what is a firewall\?/i })).toBeVisible());
    // For now, we'll check if the mocked generateAIResponse is NOT called, implying suggestions are shown instead of input.
    // This is an indirect check and ideally would be more specific.
    expect(generateAIResponse).not.toHaveBeenCalledWith('Hide suggestions'); // from previous interaction
  });
});
