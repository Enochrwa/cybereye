

/**
 * Filter an object array by fields and format for CSV or JSON export
 * 
 * @param data The array of objects to filter and format
 * @param fields The list of fields to include in the output
 * @param format The output format ('csv' or 'json')
 * @returns Formatted data string
 */
export const filterAndFormatData = <T extends Record<string, any>>(
  data: T[], 
  fields: string[], 
  format: 'csv' | 'json'
): string => {
  if (format === 'csv') {
    // Create the CSV header
    let csv = fields.join(',') + '\n';
    
    // Add each row
    data.forEach(item => {
      const values = fields.map(field => {
        const value = item[field];
        
        // Handle nested objects, arrays, null and undefined values
        if (value === null || value === undefined) {
          return '';
        } else if (typeof value === 'object') {
          return `"${JSON.stringify(value).replace(/"/g, '""')}"`;
        } else {
          // Escape quotes and wrap string values in quotes
          return typeof value === 'string' ? `"${value.replace(/"/g, '""')}"` : value;
        }
      });
      
      csv += values.join(',') + '\n';
    });
    
    return csv;
  } else {
    // Format as JSON
    const filteredData = data.map(item => {
      const filteredItem: Record<string, any> = {};
      fields.forEach(field => {
        filteredItem[field] = item[field];
      });
      return filteredItem;
    });
    
    return JSON.stringify(filteredData, null, 2);
  }
};

/**
 * Export data to CSV format
 * 
 * @param data The array of objects to export
 * @param filename The filename for the download
 */
export const exportToCSV = <T extends Record<string, any>>(data: T[], filename: string): void => {
  if (!data || data.length === 0) {
    console.warn('No data to export');
    return;
  }
  
  const fields = Object.keys(data[0] || {});
  const csvContent = filterAndFormatData(data, fields, 'csv');
  
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `${filename}.csv`);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  // Clean up the URL object
  setTimeout(() => URL.revokeObjectURL(url), 100);
};

/**
 * Export data to JSON format
 * 
 * @param data The array of objects to export
 * @param filename The filename for the download
 */
export const exportToJSON = <T extends Record<string, any>>(data: T[], filename: string): void => {
  if (!data || data.length === 0) {
    console.warn('No data to export');
    return;
  }
  
  const jsonContent = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonContent], { type: 'application/json' });
  const link = document.createElement('a');
  
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `${filename}.json`);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  // Clean up the URL object
  setTimeout(() => URL.revokeObjectURL(url), 100);
};

/**
 * Format a date string to a human-readable format
 * 
 * @param dateString The date string to format
 * @param includeTime Whether to include time in the formatted string
 * @returns Formatted date string
 */
export const formatDate = (dateString: string, includeTime: boolean = true): string => {
  const date = new Date(dateString);
  
  if (isNaN(date.getTime())) {
    return dateString; // Return original if invalid
  }
  
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    ...(includeTime && {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  };
  
  return new Intl.DateTimeFormat('en-US', options).format(date);
};

/**
 * Format bytes to human readable string (KB, MB, GB)
 * 
 * @param bytes Number of bytes
 * @param decimals Decimal places in result
 * @returns Formatted size string
 */
export const formatBytes = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
};

/**
 * Truncate text to a specific length and add ellipsis
 * 
 * @param text The text to truncate
 * @param maxLength Maximum length before truncating
 * @returns Truncated text
 */
export const truncateText = (text: string, maxLength: number = 50): string => {
  if (!text) return '';
  return text.length > maxLength ? `${text.substring(0, maxLength)}...` : text;
};
