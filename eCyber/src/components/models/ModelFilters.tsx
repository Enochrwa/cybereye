
import React from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Search, Filter, SlidersHorizontal } from 'lucide-react';

interface ModelFiltersProps {
  onSearch: (term: string) => void;
  onFilterChange: (filter: string) => void;
  onStatusChange: (statuses: string[]) => void;
  selectedStatuses: string[];
}

const ModelFilters = ({ onSearch, onFilterChange, onStatusChange, selectedStatuses }: ModelFiltersProps) => {
  const handleStatusToggle = (status: string) => {
    if (selectedStatuses.includes(status)) {
      onStatusChange(selectedStatuses.filter(s => s !== status));
    } else {
      onStatusChange([...selectedStatuses, status]);
    }
  };

  return (
    <div className="bg-card/70 backdrop-blur-sm border border-border rounded-lg p-4 mb-6 animate-fade-in">
      <div className="flex flex-col md:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
          <Input 
            placeholder="Search models..." 
            className="pl-9" 
            onChange={(e) => onSearch(e.target.value)}
          />
        </div>
        
        <div className="flex gap-3">
          <Select onValueChange={onFilterChange}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="accuracy-high">Accuracy: High to Low</SelectItem>
              <SelectItem value="accuracy-low">Accuracy: Low to High</SelectItem>
              <SelectItem value="name-asc">Name: A to Z</SelectItem>
              <SelectItem value="name-desc">Name: Z to A</SelectItem>
              <SelectItem value="recent">Recently Trained</SelectItem>
            </SelectContent>
          </Select>
          
          <div className="relative">
            <div className="flex items-center gap-4 border border-border rounded-md px-3 py-2">
              <SlidersHorizontal className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm">Status:</span>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <Checkbox 
                    id="status-active" 
                    checked={selectedStatuses.includes('active')}
                    onCheckedChange={() => handleStatusToggle('active')}
                  />
                  <Label htmlFor="status-active" className="text-sm cursor-pointer">Active</Label>
                </div>
                <div className="flex items-center gap-1.5">
                  <Checkbox 
                    id="status-training" 
                    checked={selectedStatuses.includes('training')}
                    onCheckedChange={() => handleStatusToggle('training')}
                  />
                  <Label htmlFor="status-training" className="text-sm cursor-pointer">Training</Label>
                </div>
                <div className="flex items-center gap-1.5">
                  <Checkbox 
                    id="status-inactive" 
                    checked={selectedStatuses.includes('inactive')}
                    onCheckedChange={() => handleStatusToggle('inactive')}
                  />
                  <Label htmlFor="status-inactive" className="text-sm cursor-pointer">Inactive</Label>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelFilters;
