import jaroWinkler from 'jaro-winkler';
import knowledgeBaseData from './KnowledgeBase.json'
import { Message } from './types'; // Assuming types.ts exists and defines Message

// Function to get time display format (integrated from existing utils.ts)
export const getTimeDisplay = (date: Date): string => {
  return date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
};

// Define a type for the knowledge base items
export interface KnowledgeBaseItem {
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

// Type guard to check if an item is a KnowledgeBaseItem
function isKnowledgeBaseItem(item: any): item is KnowledgeBaseItem {
  return typeof item === 'object' &&
         item !== null &&
         typeof item.id === 'string' &&
         typeof item.name === 'string' &&
         Array.isArray(item.keywords) &&
         item.keywords.every(kw => typeof kw === 'string') && // Ensure keywords are strings
         typeof item.description === 'string' &&
         Array.isArray(item.components) &&
         item.components.every(comp => // Ensure components have the right structure
            typeof comp === 'object' && comp !== null &&
            typeof comp.name === 'string' &&
            typeof comp.type === 'string' &&
            typeof comp.description === 'string'
         );
}

// Validate and type cast the imported knowledge base
// Cast knowledgeBaseData to array of any before filtering
const typedKnowledgeBase: KnowledgeBaseItem[] = Array.isArray(knowledgeBaseData)
  ? (knowledgeBaseData as any[]).filter(isKnowledgeBaseItem)
  : [];

// Warn if some items were filtered out
if (Array.isArray(knowledgeBaseData) && typedKnowledgeBase.length !== knowledgeBaseData.length) {
  console.warn("AI Assistant: Some items in knowledgeBase.json were filtered out due to invalid structure or missing fields.");
}


export const generateAIResponse = (userInput: string): { responseText: string; category?: Message['category']; tags?: string[] } => {
  const inputWords = userInput.toLowerCase().split(/\s+/).filter(word => word.length > 2);
  let bestMatch: KnowledgeBaseItem | null = null;
  let highestScore = 0.0;

  const SIMILARITY_THRESHOLD = 0.8; // For individual keyword matching

  typedKnowledgeBase.forEach((item: KnowledgeBaseItem) => {
    let currentItemScore = 0;
    let matchedKeywordsCount = 0;

    item.keywords.forEach(kw => {
      const keyword = kw.toLowerCase();
      let maxSimilarityForKeyword = 0;
      inputWords.forEach(inputWord => {
        const similarity = jaroWinkler(inputWord, keyword);
        if (similarity > maxSimilarityForKeyword) {
          maxSimilarityForKeyword = similarity;
        }
      });

      if (maxSimilarityForKeyword > SIMILARITY_THRESHOLD) {
        currentItemScore += maxSimilarityForKeyword;
        matchedKeywordsCount++;
      }
    });
    
    if (matchedKeywordsCount > 0) {
      // Favor items that match more of the user's input words
      const inputCoverage = matchedKeywordsCount / inputWords.length;
      // Favor items where more of its own keywords are matched
      const itemKeywordCoverage = matchedKeywordsCount / item.keywords.length;
      // Average score of matched keywords
      const averageKeywordScore = currentItemScore / matchedKeywordsCount;

      // Weighted average to prioritize better, more comprehensive matches
      const finalScore = (averageKeywordScore * 0.5) + (itemKeywordCoverage * 0.3) + (inputCoverage * 0.2);

      if (finalScore > highestScore) {
        highestScore = finalScore;
        bestMatch = item;
      }
    }
  });
  
  // Use a threshold relative to the similarity threshold to determine if a match is good enough
  if (bestMatch && highestScore > (SIMILARITY_THRESHOLD * 0.75)) { // Adjusted threshold
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
    
    response = response.trim();

    return {
      responseText: response,
      category: bestMatch.id as Message['category'], // Cast id to Message['category']
      tags: bestMatch.keywords,
    };
  }

  return {
    responseText: "I'm sorry, I couldn't find specific information related to your query. Could you try rephrasing or asking about a different topic? For example, 'What is threat intelligence?' or 'Tell me about the firewall'.",
    category: 'unknown',
    tags: [],
  };
};
