
import React, { useState, useEffect, useCallback } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Shield, Globe, AlertOctagon, Activity, Eye, RefreshCw, Bell, Loader2 } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";

interface FeedData {
  id: string; // From backend: threatfox, cve_circl
  name: string;
  status: string; // 'active', 'error', 'pending/unfetched'
  entries: number;
  last_updated?: string | null; // ISO string or null
  source_url?: string | null;
  is_subscribed: boolean;
  // Frontend specific
  icon: React.ElementType;
  description: string;
  isExpanded?: boolean; // UI state
}

const feedDetailsMap: Record<string, { icon: React.ElementType; description: string }> = {
  threatfox: { icon: Globe, description: 'ThreatFox IOCs - Open-source platform for sharing indicators of compromise (IOCs).' },
  cve_circl: { icon: Activity, description: 'CIRCL CVEs - Vulnerabilities reported by Computer Incident Response Center Luxembourg.' },
  default: { icon: Shield, description: 'General threat intelligence feed.'}
};

const ThreatFeedsInteractive = () => {
  const [threatFeedsData, setThreatFeedsData] = useState<FeedData[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchThreatFeeds = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/threat-intelligence/feeds');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data: Omit<FeedData, 'icon' | 'description' | 'isExpanded'>[] = await response.json();
      const processedData: FeedData[] = data.map(feed => ({
        ...feed,
        icon: feedDetailsMap[feed.id]?.icon || feedDetailsMap.default.icon,
        description: feedDetailsMap[feed.id]?.description || feedDetailsMap.default.description,
        isExpanded: false, // Default UI state
      }));
      setThreatFeedsData(processedData);
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : 'An unknown error occurred';
      setError(errorMessage);
      console.error("Failed to fetch threat feeds:", e);
      toast({ title: "Error Fetching Feeds", description: errorMessage, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    fetchThreatFeeds();
  }, [fetchThreatFeeds]);
  
  const toggleExpand = (id: string) => {
    setThreatFeedsData(feeds => 
      feeds.map(feed => 
        feed.id === id ? { ...feed, isExpanded: !feed.isExpanded } : feed
      )
    );
  };
  
  const toggleSubscription = async (feedId: string, currentIsSubscribed: boolean) => {
    const newSubscriptionStatus = !currentIsSubscribed;
    try {
      const response = await fetch(`http://127.0.0.1:800/api/v1/threat-intelligence/feeds/${feedId}/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_subscribed: newSubscriptionStatus }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }
      const updatedFeed: Omit<FeedData, 'icon' | 'description' | 'isExpanded'> = await response.json();
      
      setThreatFeedsData(feeds => 
        feeds.map(feed => 
          feed.id === feedId ? { 
            ...feed, 
            is_subscribed: updatedFeed.is_subscribed,
            // Potentially update other fields if the API returns them on subscribe
            // For example, if subscribing triggers an immediate refresh by the backend:
            status: updatedFeed.status,
            entries: updatedFeed.entries,
            last_updated: updatedFeed.last_updated,
          } : feed
        )
      );
      toast({
        title: newSubscriptionStatus ? "Subscription Activated" : "Subscription Deactivated",
        description: `${updatedFeed.name} is now ${newSubscriptionStatus ? 'subscribed' : 'unsubscribed'}.`,
        variant: newSubscriptionStatus ? "default" : "destructive",
      });
      // If subscribing triggers a refresh, and you want to ensure data consistency immediately
      // you might call fetchThreatFeeds() here, or trust the backend's response.
      // For now, we update based on the direct response from subscribe endpoint.
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : 'Failed to update subscription';
      console.error("Failed to toggle subscription:", e);
      toast({ title: "Subscription Error", description: errorMessage, variant: "destructive" });
    }
  };
  
  const refreshFeed = async (feedId: string) => {
    toast({ title: "Refreshing Feed", description: `Requesting latest data for ${feedId}...` });
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/v1/threat-intelligence/feeds/${feedId}/refresh`, { method: 'POST' });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }
      // The refresh endpoint response includes: feed_id, status, last_updated, entry_count, error, message
      // We should re-fetch all feeds to get the most consistent state,
      // as refresh might affect other computed properties or one feed might affect another in future.
      // Alternatively, parse the response and update the specific feed if the response is comprehensive.
      // For simplicity and consistency:
      await fetchThreatFeeds(); 
      toast({ title: "Feed Refresh Requested", description: `Feed ${feedId} data is being updated.`, variant: "default" });
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : 'Failed to refresh feed';
      console.error("Failed to refresh feed:", e);
      toast({ title: "Refresh Error", description: errorMessage, variant: "destructive" });
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-base flex items-center"><Bell className="mr-2" size={18} />Threat Intelligence Feeds</CardTitle></CardHeader>
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <p className="ml-2">Loading feeds...</p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-base flex items-center"><Bell className="mr-2" size={18} />Threat Intelligence Feeds</CardTitle></CardHeader>
        <CardContent className="text-red-500 py-4 text-center">Error fetching feeds: {error}</CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center">
          <Bell className="mr-2" size={18} />
          Threat Intelligence Feeds
        </CardTitle>
      </CardHeader>
      <CardContent>
        {threatFeedsData.length === 0 && !isLoading && (
           <div className="text-muted-foreground py-4 text-center">No threat feeds available.</div>
        )}
        <div className="space-y-4">
          {threatFeedsData.map((feed) => (
            <div 
              key={feed.id} 
              className={cn(
                "border border-border rounded-lg transition-all",
                feed.isExpanded ? "bg-muted/30" : ""
              )}
            >
              <div 
                className="flex items-center justify-between p-4 cursor-pointer"
                onClick={() => toggleExpand(feed.id)}
              >
                <div className="flex items-center">
                  <div className={cn(
                    "w-10 h-10 rounded-full flex items-center justify-center mr-3",
                    feed.status === 'active' && feed.is_subscribed ? "bg-green-500/10 text-green-500" 
                    : (!feed.is_subscribed ? "bg-gray-500/10 text-gray-500" 
                    : "bg-amber-500/10 text-amber-500") // For 'error' or 'pending' status
                  )}>
                    <feed.icon size={20} />
                  </div>
                  <div>
                    <div className="font-medium">{feed.name}</div>
                    <div className="text-xs text-muted-foreground">{feed.entries} entries</div>
                  </div>
                </div>
                <div className="text-right">
                  <Badge 
                    variant="outline" 
                    className={cn(
                      feed.status === 'active' && feed.is_subscribed ? "bg-green-500/10 text-green-500" 
                      : (!feed.is_subscribed ? "bg-gray-500/10 text-gray-500"
                      : "bg-amber-500/10 text-amber-500")
                    )}
                  >
                    {feed.is_subscribed ? (feed.status === 'active' ? 'Active' : (feed.status === 'error' ? 'Error' : 'Pending')) : 'Unsubscribed'}
                  </Badge>
                  <div className="text-xs text-muted-foreground mt-1">
                    {feed.last_updated ? `Updated ${new Date(feed.last_updated).toLocaleTimeString()} ${new Date(feed.last_updated).toLocaleDateString()}` : 'Not updated yet'}
                  </div>
                </div>
              </div>
              
              {feed.isExpanded && (
                <div className="p-4 pt-0 border-t border-border mt-2">
                  <p className="text-sm mb-3">{feed.description}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Button 
                        size="sm" 
                        variant="outline" 
                        disabled={!feed.is_subscribed}
                        onClick={(e) => {
                          e.stopPropagation();
                          if(feed.is_subscribed) refreshFeed(feed.id);
                        }}
                      >
                        <RefreshCw className="mr-2 h-3.5 w-3.5" />
                        Refresh Feed
                      </Button>
                      {/* View Details button can be kept for future functionality */}
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          toast({
                            title: "Feed Details",
                            description: `Name: ${feed.name}\nSource: ${feed.source_url || 'N/A'}\nEntries: ${feed.entries}`,
                          });
                        }}
                      >
                        <Eye className="mr-2 h-3.5 w-3.5" />
                        View Details
                      </Button>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">Subscribed</span>
                      <Switch 
                        checked={feed.is_subscribed}
                        onCheckedChange={() => toggleSubscription(feed.id, feed.is_subscribed)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatFeedsInteractive;
