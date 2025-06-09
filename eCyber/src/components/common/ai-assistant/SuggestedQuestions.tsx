
import React from 'react';
import { ChevronDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SUGGESTED_QUESTIONS } from './constants';

interface SuggestedQuestionsProps {
  onSuggestionClick: (question: string) => void;
}

const SuggestedQuestions: React.FC<SuggestedQuestionsProps> = ({ onSuggestionClick }) => {
  return (
    <div className="px-4 py-2">
      <p className="text-xs text-muted-foreground mb-2">Suggested questions:</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {SUGGESTED_QUESTIONS.map((q, i) => (
          <Button 
            key={i}
            variant="outline"
            size="sm"
            className="justify-start text-left h-auto py-1.5"
            onClick={() => onSuggestionClick(q)}
          >
            <ChevronDown className="mr-1 h-3 w-3 text-muted-foreground" />
            <span className="truncate text-xs">{q}</span>
          </Button>
        ))}
      </div>
    </div>
  );
};

export default SuggestedQuestions;
