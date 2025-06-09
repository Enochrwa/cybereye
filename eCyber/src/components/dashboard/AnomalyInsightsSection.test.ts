import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event'; // For more realistic interactions
import AnomalyInsightsSection from './AnomalyInsightsSection';

// --- Mocks ---

// Mock API client functions
// These paths assume the component file (AnomalyInsightsSection.tsx) is in the same directory as this test file,
// or that jest moduleNameMapper is configured if they are in different locations (e.g. a utils/api.ts file)
// For this setup, we'll assume they are co-located or mapped.
// If the actual functions are in a separate file like `../utils/apiClient`, adjust the path.
// For now, let's assume they are defined within AnomalyInsightsSection.tsx for simplicity of mocking.
// This is a common pattern if they aren't exported from the component file itself.

// To mock functions defined within the component file and not exported,
// we need to mock the module itself.
// If they were in a separate file, e.g., './apiService', we'd mock that path.
// Since the prompt implies they are part of the component's context (though implemented as standalone async fns)
// we will mock the module.
const mockFetchAnomalySummary = jest.fn();
const mockFetchAnomalyTrends = jest.fn();
const mockFetchAnomalyTable = jest.fn();
const mockFetchAnomalyDetail = jest.fn();

// Mocking the module where AnomalyInsightsSection is defined,
// then selectively unmocking the component itself but keeping mocks for API functions.
// This is a bit advanced; simpler would be to have API functions in a separate file.
// For now, we'll mock specific fetch functions assuming they might be globally available or imported.
// The most robust way is to have API calls in a separate module and mock that module.
// Let's assume for this test they are from a service that can be mocked:
jest.mock('./AnomalyInsightsSection', () => {
  const originalModule = jest.requireActual('./AnomalyInsightsSection');
  return {
    __esModule: true,
    ...originalModule, // Export all actual members
    // Override the fetch functions if they were exported from the module.
    // If they are internal, this approach won't work directly.
    // Let's assume they are not exported and will be globally mocked via jest.spyOn or by mocking fetch.
  };
});


// Mock Recharts
jest.mock('recharts', () => {
  const OriginalRecharts = jest.requireActual('recharts');
  return {
    ...OriginalRecharts,
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div data-testid="responsive-container-mock">{children}</div>,
    LineChart: ({ children }: { children: React.ReactNode }) => <div data-testid="line-chart-mock">{children}</div>,
    BarChart: ({ children }: { children: React.ReactNode }) => <div data-testid="bar-chart-mock">{children}</div>,
    RadarChart: ({ children }: { children: React.ReactNode }) => <div data-testid="radar-chart-mock">{children}</div>,
    Line: () => <div data-testid="recharts-line-mock" />,
    Bar: () => <div data-testid="recharts-bar-mock" />,
    Radar: () => <div data-testid="recharts-radar-mock" />,
    XAxis: () => <div data-testid="recharts-xaxis-mock" />,
    YAxis: () => <div data-testid="recharts-yaxis-mock" />,
    CartesianGrid: () => <div data-testid="recharts-cartesiangrid-mock" />,
    Tooltip: () => <div data-testid="recharts-tooltip-mock" />,
    Legend: () => <div data-testid="recharts-legend-mock" />,
    PolarGrid: () => <div data-testid="recharts-polargrid-mock" />,
    PolarAngleAxis: () => <div data-testid="recharts-polarangleaxis-mock" />,
    PolarRadiusAxis: () => <div data-testid="recharts-polarradiusaxis-mock" />,
  };
});

// Mock global fetch
global.fetch = jest.fn();

const mockSummaryData = {
  total_anomaly_alerts: 150,
  benign_percentage: 60.55,
  malicious_percentage: 39.45,
  average_anomaly_score_24h: 0.7891,
  top_3_anomaly_patterns: [
    { type: 'RuleA', count: 50 },
    { type: 'RuleB', count: 40 },
  ],
};

const mockTrendsData = {
  threats_over_time: [{ time_bucket: new Date().toISOString(), count: 10 }],
  anomaly_score_heatmap_data: [{ time_bucket: '2023-01-01', score_range: '0.8-0.9', count: 5 }],
  threat_origins: [{ country: 'USA', count: 20 }],
};

const mockTableDataPage1 = {
  items: [
    { id: '1', timestamp: new Date().toISOString(), threat_type: 'Anomaly', anomaly_score: 0.92, verdict: 'Malicious', source_ip: '1.2.3.4', destination_ip: '5.6.7.8', destination_port: 80, protocol: 'TCP' },
    { id: '2', timestamp: new Date().toISOString(), threat_type: 'Anomaly', anomaly_score: 0.12, verdict: 'Benign', source_ip: '1.2.3.5', destination_ip: '5.6.7.9', destination_port: 443, protocol: 'TCP' },
  ],
  total: 2,
  page: 1,
  size: 10,
  pages: 1,
};

const mockTableDataPage2 = {
  items: [
    { id: '3', timestamp: new Date().toISOString(), threat_type: 'Anomaly', anomaly_score: 0.88, verdict: 'Malicious', source_ip: '1.2.3.6', destination_ip: '5.6.7.10', destination_port: 8080, protocol: 'UDP' },
  ],
  total: 3, // Assuming total items count allows for a second page
  page: 2,
  size: 1, // if pagesize was 1
  pages: 3,
};


const mockDetailData = {
  id: '1',
  timestamp: new Date().toISOString(),
  threat_type: 'Anomaly',
  anomaly_score: 0.92,
  verdict: 'Malicious',
  source_ip: '1.2.3.4',
  destination_ip: '5.6.7.8',
  destination_port: 80,
  protocol: 'TCP',
  description: 'Detailed description of the anomaly.',
  rule_id: 'RULE_ANOM_001',
  feature_contributions: [{ feature_name: 'Bytes Sent', value: 0.8 }],
  flow_metadata: { duration_seconds: 60 },
  raw_alert_data: { some_key: 'some_value' },
};


describe('AnomalyInsightsSection', () => {
  beforeEach(() => {
    // Reset mocks before each test
    (global.fetch as jest.Mock).mockReset();

    // Default successful responses
    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url.includes('/summary?threat_type=Anomaly')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockSummaryData) });
      }
      if (url.includes('/trends?threat_type=Anomaly')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTrendsData) });
      }
      if (url.includes('/threats?')) { // For table data
        if (url.includes('page=2')) {
           return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTableDataPage2) });
        }
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTableDataPage1) });
      }
      if (url.match(/\/threats\/\w+/)) { // For detail data
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockDetailData) });
      }
      return Promise.reject(new Error(`Unhandled API call: ${url}`));
    });
  });

  test('renders main title and initial loading states', async () => {
    render(<AnomalyInsightsSection />);
    expect(screen.getByText('Anomaly Insights')).toBeInTheDocument();
    // Check for initial loading indicators (example, could be more specific)
    expect(screen.getAllByText(/Loading summary...|Loading trends...|Loading anomaly logs.../i).length).toBeGreaterThanOrEqual(1);
    await waitFor(() => expect(screen.queryByText(/Loading summary.../i)).not.toBeInTheDocument()); // Wait for all loading to finish
  });

  test('fetches and displays summary data', async () => {
    render(<AnomalyInsightsSection />);
    await waitFor(() => {
      expect(screen.getByText('Total Anomaly Alerts')).toBeInTheDocument();
      expect(screen.getByText(mockSummaryData.total_anomaly_alerts.toLocaleString())).toBeInTheDocument();
      expect(screen.getByText(/Benign:/i)).toHaveTextContent(`Benign: ${mockSummaryData.benign_percentage.toFixed(2)}%`);
    });
  });

  test('fetches and displays trends data (charts)', async () => {
    render(<AnomalyInsightsSection />);
    await waitFor(() => {
      expect(screen.getByText('Alerts Over Time')).toBeInTheDocument();
      expect(screen.getByTestId('line-chart-mock')).toBeInTheDocument();
      expect(screen.getByText('Score Distribution')).toBeInTheDocument();
      expect(screen.getByTestId('bar-chart-mock')).toBeInTheDocument(); // For score distribution
      expect(screen.getByText('Top Anomaly Origins')).toBeInTheDocument();
      expect(screen.getAllByTestId('bar-chart-mock').length).toBeGreaterThanOrEqual(2); // Score dist + origins
    });
  });

  test('fetches, displays table data, and handles pagination', async () => {
    render(<AnomalyInsightsSection />);
    await waitFor(() => {
      expect(screen.getByText(mockTableDataPage1.items[0].source_ip)).toBeInTheDocument();
    });

    // Simulate clicking next page
    // Need to adjust fetch mock to handle page 2 specifically for the assertion
    (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes('page=2')) {
            return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTableDataPage2) });
        }
        // Fallback for other calls if any during this specific test interaction
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTableDataPage1) });
    });

    const nextPageButton = screen.getByRole('button', { name: /go to next page/i });
    fireEvent.click(nextPageButton);

    await waitFor(() => {
      // Check if fetch was called for page 2
      const fetchCallPage2 = (global.fetch as jest.Mock).mock.calls.find(call => call[0].includes('page=2'));
      expect(fetchCallPage2).toBeDefined();
      // And that data from page 2 is rendered (if mockTableDataPage2 is different)
      // For this test, just checking the call is enough if data isn't distinct enough or not needed.
    });
  });

  test('handles row click and fetches/displays detail in dialog', async () => {
    render(<AnomalyInsightsSection />);

    await waitFor(() => {
      expect(screen.getByText(mockTableDataPage1.items[0].source_ip)).toBeInTheDocument();
    });

    const firstRow = screen.getByText(mockTableDataPage1.items[0].source_ip).closest('tr');
    expect(firstRow).not.toBeNull();
    if(firstRow) {
        fireEvent.click(firstRow);
    }

    await waitFor(() => {
      // Check fetchAnomalyDetail was called (indirectly by selectedAnomalyId change)
      const detailFetchCall = (global.fetch as jest.Mock).mock.calls.find(call => call[0].includes(`/threats/${mockTableDataPage1.items[0].id}`));
      expect(detailFetchCall).toBeDefined();

      // Check dialog title appears
      expect(screen.getByText(`Anomaly Details - ID: ${mockTableDataPage1.items[0].id}`)).toBeInTheDocument();
      // Check some detail data
      expect(screen.getByText(mockDetailData.description!)).toBeInTheDocument();
      // Check for radar chart (mocked)
      expect(screen.getByTestId('radar-chart-mock')).toBeInTheDocument();
    });
  });

});