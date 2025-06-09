import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Grid, Typography, Card, CardContent, CircularProgress, Alert, Divider,
  TableContainer, Table, TableHead, TableBody, TableRow, TableCell, TablePagination, Paper, TableSortLabel,
  Dialog, DialogTitle, DialogContent, DialogActions, Button, IconButton, List, ListItem, ListItemText, Collapse
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { styled } from '@mui/material/styles';

import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, Cell, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';

// --- Types/Interfaces ---
// Ensure any new types like ExpandMoreProps are defined if needed, or use existing ones.
interface ExpandMoreProps extends React.HTMLAttributes<HTMLElement> {
  expand: boolean;
}

const ExpandMore = styled((props: ExpandMoreProps) => {
  const { expand, ...other } = props;
  return <IconButton {...other} />;
})(({ theme, expand }) => ({
  transform: !expand ? 'rotate(0deg)' : 'rotate(180deg)',
  marginLeft: 'auto',
  transition: theme.transitions.create('transform', {
    duration: theme.transitions.duration.shortest,
  }),
}));


interface ThreatAnalysisTopType {
  type: string;
  count: number;
}

interface ThreatAnalysisSummary {
  total_threats: number;
  benign_percentage: number;
  malicious_percentage: number;
  average_anomaly_score_24h?: number | null;
  retraining_last_occurred?: string | null;
  top_3_attack_types: ThreatAnalysisTopType[];
}

interface ThreatAnalysisTrendPoint {
  time_bucket: string;
  count: number;
}

interface ThreatAnalysisScoreHeatmapPoint {
  time_bucket: string;
  score_range: string;
  count: number;
}

interface ThreatAnalysisOriginPoint {
  country: string;
  count: number;
}

interface ThreatAnalysisModelDecisionPoint {
  model_name: string;
  above_threshold_count: number;
  below_threshold_count: number;
}

interface ThreatAnalysisTrends {
  threats_over_time: ThreatAnalysisTrendPoint[];
  anomaly_score_heatmap_data: ThreatAnalysisScoreHeatmapPoint[];
  threat_origins: ThreatAnalysisOriginPoint[];
  model_decision_stats: ThreatAnalysisModelDecisionPoint[];
}

interface ThreatAnalysisTableRow {
  id: string;
  timestamp: string;
  threat_type: string;
  anomaly_score?: number | null;
  verdict: string;
  source_ip: string;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
}

interface PaginatedThreatAnalysisTableResponse {
  total: number;
  items: ThreatAnalysisTableRow[];
  page: number;
  size: number;
  pages: number;
}

// For Threat Detail View
interface ThreatFlowFeature {
  feature_name: string;
  value: number; // Assuming numeric feature values for a radar chart
}

interface ThreatFlowMetadataDetail {
  packet_counts?: { [key: string]: number } | null;
  duration_seconds?: number | null;
  flags_summary?: { [key: string]: number } | null;
  active_idle_stats?: { [key: string]: number } | null;
  payload_length_stats?: { [key: string]: number } | null;
  raw_features?: { [key: string]: any } | null;
}

interface ThreatAnalysisDetailResponse extends ThreatAnalysisTableRow {
  description?: string | null;
  rule_id?: string | null;
  category?: string | null;
  severity?: string | null;
  feature_contributions?: ThreatFlowFeature[] | null;
  flow_metadata?: ThreatFlowMetadataDetail | null;
  raw_alert_data?: { [key: string]: any } | null;
}


type SortDirection = 'asc' | 'desc';

interface SortConfig {
  key: string;
  direction: SortDirection;
}


// --- API Client Functions ---
async function fetchThreatSummary(): Promise<ThreatAnalysisSummary> {
  const response = await fetch('http://127.0.0.1:8000/api/v1/threat-analysis/summary');
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch threat summary: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse threat summary response: ${e}`);
  }
}

async function fetchThreatTrends(): Promise<ThreatAnalysisTrends> {
  const response = await fetch('/api/v1/threat-analysis/trends');
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch threat trends: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse threat trends response: ${e}`);
  }
}

async function fetchThreatsTable(
  page: number,
  size: number,
  sortBy?: string,
  sortDesc?: boolean,
): Promise<PaginatedThreatAnalysisTableResponse> {
  const params = new URLSearchParams({
    page: String(page),
    size: String(size),
  });
  if (sortBy) {
    params.append('sort_by', sortBy);
    if (sortDesc !== undefined) {
      params.append('sort_desc', String(sortDesc));
    }
  }
  const response = await fetch(`/api/v1/threat-analysis/threats?${params.toString()}`);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch threats table: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse threats table response: ${e}`);
  }
}

async function fetchThreatDetail(threatId: string): Promise<ThreatAnalysisDetailResponse> {
  const response = await fetch(`/api/v1/threat-analysis/threats/${threatId}`);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch threat detail for ID ${threatId}: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse threat detail response: ${e}`);
  }
}


const ThreatAnalysisDashboard: React.FC = () => {
  // Summary State
  const [summaryData, setSummaryData] = useState<ThreatAnalysisSummary | null>(null);
  const [isSummaryLoading, setIsSummaryLoading] = useState<boolean>(true);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  // Trends State
  const [trendsData, setTrendsData] = useState<ThreatAnalysisTrends | null>(null);
  const [isTrendsLoading, setIsTrendsLoading] = useState<boolean>(true);
  const [trendsError, setTrendsError] = useState<string | null>(null);

  // Table State
  const [tableData, setTableData] = useState<PaginatedThreatAnalysisTableResponse | null>(null);
  const [isTableLoading, setIsTableLoading] = useState<boolean>(true);
  const [tableError, setTableError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(0);
  const [pageSize, setPageSize] = useState<number>(10);
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: 'timestamp', direction: 'desc' });

  // Detail View State
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [threatDetailData, setThreatDetailData] = useState<ThreatAnalysisDetailResponse | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState<boolean>(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [rawAlertExpanded, setRawAlertExpanded] = useState(false);


  const loadTableData = useCallback(async () => {
    setIsTableLoading(true);
    try {
      const data = await fetchThreatsTable(
        currentPage + 1,
        pageSize,
        sortConfig.key,
        sortConfig.direction === 'desc'
      );
      setTableData(data);
      setTableError(null);
    } catch (err) {
      console.error("Error loading table data:", err);
      setTableError(err instanceof Error ? err.message : 'An unknown error occurred');
      setTableData(null);
    } finally {
      setIsTableLoading(false);
    }
  }, [currentPage, pageSize, sortConfig]);

  useEffect(() => {
    const loadInitialData = async () => {
      setIsSummaryLoading(true);
      setIsTrendsLoading(true);
      setIsTableLoading(true); // Table also loads initially

      const results = await Promise.allSettled([
        fetchThreatSummary(),
        fetchThreatTrends(),
        fetchThreatsTable(1, pageSize, sortConfig.key, sortConfig.direction === 'desc')
      ]);

      // Summary
      if (results[0].status === 'fulfilled') {
        setSummaryData(results[0].value as ThreatAnalysisSummary);
        setSummaryError(null);
      } else {
        console.error("Error loading summary data:", results[0].reason);
        setSummaryError(results[0].reason instanceof Error ? results[0].reason.message : 'Unknown summary error');
      }
      setIsSummaryLoading(false);

      // Trends
      if (results[1].status === 'fulfilled') {
        setTrendsData(results[1].value as ThreatAnalysisTrends);
        setTrendsError(null);
      } else {
        console.error("Error loading trends data:", results[1].reason);
        setTrendsError(results[1].reason instanceof Error ? results[1].reason.message : 'Unknown trends error');
      }
      setIsTrendsLoading(false);

      // Table
      if (results[2].status === 'fulfilled') {
        setTableData(results[2].value as PaginatedThreatAnalysisTableResponse);
        setTableError(null);
        // If API returns 0-indexed page, adjust here. Assuming API is 1-indexed.
        // setCurrentPage((results[2].value as PaginatedThreatAnalysisTableResponse).page - 1);
      } else {
        console.error("Error loading initial table data:", results[2].reason);
        setTableError(results[2].reason instanceof Error ? results[2].reason.message : 'Unknown table error');
      }
      setIsTableLoading(false);
    };
    loadInitialData();
  }, [pageSize]); // Reload initial data if pageSize changes from a previous session? Or keep it simple. For now, just initial.

  useEffect(() => {
    // Don't run on initial mount if loadInitialData already fetched it.
    // This is primarily for subsequent changes to page, size, sort.
    if (!isTableLoading && !isSummaryLoading && !isTrendsLoading) { // Avoid race with initial load
        loadTableData();
    }
  }, [currentPage, pageSize, sortConfig, loadTableData]);


  const loadThreatDetail = async (threatId: string) => {
    setIsDetailLoading(true);
    setDetailError(null);
    try {
      const data = await fetchThreatDetail(threatId);
      setThreatDetailData(data);
    } catch (err) {
      console.error(`Error loading threat detail for ID ${threatId}:`, err);
      setDetailError(err instanceof Error ? err.message : 'An unknown error occurred');
      setThreatDetailData(null);
    } finally {
      setIsDetailLoading(false);
    }
  };

  const handleSortRequest = (propertyKey: string) => {
    const isAsc = sortConfig.key === propertyKey && sortConfig.direction === 'asc';
    setSortConfig({ key: propertyKey, direction: isAsc ? 'desc' : 'asc' });
    setCurrentPage(0);
  };

  const handlePageChange = (event: unknown, newPage: number) => {
    setCurrentPage(newPage);
  };

  const handleRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setPageSize(parseInt(event.target.value, 10));
    setCurrentPage(0);
  };

  const handleRowClick = (threatId: string) => {
    if (selectedThreatId === threatId) {
      setSelectedThreatId(null); // Toggle off if already selected
      setThreatDetailData(null);
      setDetailError(null);
    } else {
      setSelectedThreatId(threatId);
      loadThreatDetail(threatId);
    }
  };

  const handleCloseDetailView = () => {
    setSelectedThreatId(null);
    setThreatDetailData(null);
    setDetailError(null);
    setRawAlertExpanded(false);
  };

  const handleRawAlertExpandClick = () => {
    setRawAlertExpanded(!rawAlertExpanded);
  };


  const formatTimestamp = (isoString: string | undefined | null) => {
    if (!isoString) return 'N/A';
    try {
      return new Date(isoString).toLocaleString();
    } catch (e) {
      return isoString;
    }
  };

  const formatDateTick = (tickItem: string) => {
    try {
      const date = new Date(tickItem);
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch (e) { return tickItem; }
  };

  if (isSummaryLoading && isTrendsLoading && isTableLoading && !summaryData && !trendsData && !tableData) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" sx={{ height: 'calc(100vh - 100px)' }}>
        <CircularProgress />
      </Box>
    );
  }

  const tableColumns: { id: keyof ThreatAnalysisTableRow | 'actions' ; label: string; minWidth?: number, numeric?: boolean, sortable?: boolean }[] = [
    { id: 'timestamp', label: 'Timestamp', minWidth: 170, sortable: true }, { id: 'threat_type', label: 'Threat Type', minWidth: 150, sortable: true }, { id: 'anomaly_score', label: 'Anomaly Score', minWidth: 100, numeric: true, sortable: true }, { id: 'verdict', label: 'Verdict', minWidth: 100, sortable: true }, { id: 'source_ip', label: 'Source IP', minWidth: 120, sortable: true }, { id: 'destination_ip', label: 'Dest. IP', minWidth: 120, sortable: true }, { id: 'destination_port', label: 'Dest. Port', minWidth: 100, numeric: true, sortable: true }, { id: 'protocol', label: 'Protocol', minWidth: 80, sortable: true },
  ];

  const renderDetailItem = (label: string, value: string | number | undefined | null) => (
    value !== null && value !== undefined && String(value).trim() !== '' && String(value) !== 'N/A' ? (
      <ListItem dense>
        <ListItemText primary={String(value)} secondary={label} />
      </ListItem>
    ) : null
  );

  const renderNestedObject = (obj: { [key: string]: any } | null | undefined, title: string) => {
    if (!obj || Object.keys(obj).length === 0) return null;
    return (
      <Box mt={2}>
        <Typography variant="subtitle1" gutterBottom>{title}</Typography>
        <Paper variant="outlined" sx={{ p: 1.5, maxHeight: 150, overflow: 'auto' }}>
          <List dense>
            {Object.entries(obj).map(([key, value]) => renderDetailItem(key, String(value)))}
          </List>
        </Paper>
      </Box>
    );
  };


  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 2 }}>Threat Analysis Dashboard</Typography>

      {isSummaryLoading ? <CircularProgress size={24} sx={{mr:1}}/> : summaryError && <Alert severity="error" sx={{mb:2}}>Failed to load summary: {summaryError}</Alert>}
      {!isSummaryLoading && !summaryData && !summaryError && <Alert severity="info" sx={{mb:2}}>No summary data available.</Alert>}
      {summaryData && ( <Grid container spacing={3} sx={{ mb: 4 }}> <Grid item xs={12} sm={6} md={4} lg={2.4}> <Card sx={{ height: '100%' }}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Total Threats</Typography> <Typography variant="h4">{summaryData.total_threats.toLocaleString()}</Typography> </CardContent> </Card> </Grid> <Grid item xs={12} sm={6} md={4} lg={2.4}> <Card sx={{ height: '100%' }}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Verdicts</Typography> <Typography variant="h6" sx={{ color: 'green' }}>Benign: {summaryData.benign_percentage.toFixed(2)}%</Typography> <Typography variant="h6" sx={{ color: 'red' }}>Malicious: {summaryData.malicious_percentage.toFixed(2)}%</Typography> </CardContent> </Card> </Grid> <Grid item xs={12} sm={6} md={4} lg={2.4}> <Card sx={{ height: '100%' }}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Avg. Anomaly Score (24h)</Typography> <Typography variant="h4">{summaryData.average_anomaly_score_24h?.toFixed(4) ?? 'N/A'}</Typography> </CardContent> </Card> </Grid> <Grid item xs={12} sm={6} md={4} lg={2.4}> <Card sx={{ height: '100%' }}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Retraining</Typography> <Typography variant="h5">{summaryData.retraining_last_occurred || 'N/A'}</Typography> </CardContent> </Card> </Grid> <Grid item xs={12} md={8} lg={2.4}> <Card sx={{ height: '100%' }}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Top Attacks</Typography> {summaryData.top_3_attack_types?.length > 0 ? summaryData.top_3_attack_types.map((a, i) => <Typography key={i} variant="body1"><strong>{a.type}:</strong> {a.count.toLocaleString()}</Typography>) : <Typography variant="body1">N/A</Typography>} </CardContent> </Card> </Grid> </Grid> )}

      <Divider sx={{ my: 4 }} />

      <Typography variant="h5" gutterBottom sx={{ mb: 3 }}>Trend Insights</Typography>
      {isTrendsLoading ? <CircularProgress size={24} sx={{mr:1}}/> : trendsError && <Alert severity="error" sx={{mb:2}}>Failed to load trends: {trendsError}</Alert>}
      {!isTrendsLoading && !trendsData && !trendsError && <Alert severity="info" sx={{mb:2}}>No trend data available.</Alert>}
      {trendsData && ( <Grid container spacing={3} sx={{mb:4}}> <Grid item xs={12} md={6}> <Card> <CardContent> <Typography variant="h6" gutterBottom>Threats Over Time</Typography> {trendsData.threats_over_time?.length > 0 ? (<ResponsiveContainer width="100%" height={300}> <LineChart data={trendsData.threats_over_time}> <CartesianGrid strokeDasharray="3 3" /> <XAxis dataKey="time_bucket" tickFormatter={formatDateTick} angle={-30} textAnchor="end" height={70}/> <YAxis allowDecimals={false}/> <Tooltip labelFormatter={(label) => formatDateTick(label)}/> <Legend /> <Line type="monotone" dataKey="count" stroke="#8884d8" name="Threats"/> </LineChart> </ResponsiveContainer>) : (<Typography>No data.</Typography>)} </CardContent> </Card> </Grid> <Grid item xs={12} md={6}> <Card> <CardContent> <Typography variant="h6" gutterBottom>Anomaly Score Distribution</Typography> {trendsData.anomaly_score_heatmap_data?.length > 0 ? (<ResponsiveContainer width="100%" height={300}> <BarChart data={trendsData.anomaly_score_heatmap_data.sort((a,b) => parseFloat(a.score_range.split('-')[0]) - parseFloat(b.score_range.split('-')[0]))}> <CartesianGrid strokeDasharray="3 3" /> <XAxis dataKey="score_range"/> <YAxis allowDecimals={false}/> <Tooltip /> <Legend /> <Bar dataKey="count" fill="#82ca9d" name="Count"/> </BarChart> </ResponsiveContainer>) : (<Typography>No data.</Typography>)} </CardContent> </Card> </Grid> <Grid item xs={12} md={6}> <Card> <CardContent> <Typography variant="h6" gutterBottom>Top Threat Origins</Typography> {trendsData.threat_origins?.length > 0 ? (<ResponsiveContainer width="100%" height={300}> <BarChart data={trendsData.threat_origins} layout="vertical"> <CartesianGrid strokeDasharray="3 3" /> <XAxis type="number" allowDecimals={false}/> <YAxis type="category" dataKey="country" width={100}/> <Tooltip /> <Legend /> <Bar dataKey="count" fill="#d4ac0d" name="Count"/> </BarChart> </ResponsiveContainer>) : (<Typography>No data.</Typography>)} </CardContent> </Card> </Grid> <Grid item xs={12} md={6}> <Card> <CardContent> <Typography variant="h6" gutterBottom>Model Performance</Typography> {trendsData.model_decision_stats?.length > 0 ? (<ResponsiveContainer width="100%" height={300}> <BarChart data={trendsData.model_decision_stats}> <CartesianGrid strokeDasharray="3 3" /> <XAxis dataKey="model_name"/> <YAxis allowDecimals={false}/> <Tooltip /> <Legend /> <Bar dataKey="above_threshold_count" stackId="a" fill="#c0392b" name="Above"/> <Bar dataKey="below_threshold_count" stackId="a" fill="#27ae60" name="Below"/> </BarChart> </ResponsiveContainer>) : (<Typography>No data.</Typography>)} </CardContent> </Card> </Grid> </Grid> )}

      <Divider sx={{ my: 4 }} />

      <Typography variant="h5" gutterBottom sx={{ mb: 3 }}>Threat Breakdown</Typography>
      {isTableLoading && !tableData?.items?.length && <Box sx={{display:'flex', justifyContent:'center', my:2}}><CircularProgress/></Box>}
      {tableError && <Alert severity="error" sx={{mb:2}}>Failed to load threats table: {tableError}</Alert>}
      <Paper sx={{ width: '100%', overflow: 'hidden' }}> <TableContainer sx={{ maxHeight: 600 }}> <Table stickyHeader> <TableHead> <TableRow> {tableColumns.map((c) => ( <TableCell key={c.id} align={c.numeric ? 'right' : 'left'} style={{ minWidth: c.minWidth }} sortDirection={sortConfig.key === c.id ? sortConfig.direction : false}> {c.sortable ? (<TableSortLabel active={sortConfig.key === c.id} direction={sortConfig.key === c.id ? sortConfig.direction : 'asc'} onClick={() => c.id !== 'actions' && handleSortRequest(c.id)}> {c.label} </TableSortLabel>) : ( c.label )} </TableCell> ))} </TableRow> </TableHead> <TableBody> {(isTableLoading && !tableData?.items?.length) ? (<TableRow><TableCell colSpan={tableColumns.length} align="center"><CircularProgress sx={{my: 2}}/></TableCell></TableRow>) : tableData?.items?.length > 0 ? ( tableData.items.map((row) => ( <TableRow hover role="checkbox" tabIndex={-1} key={row.id} onClick={() => handleRowClick(row.id)} selected={selectedThreatId === row.id} sx={{ cursor: 'pointer' }}> <TableCell>{formatTimestamp(row.timestamp)}</TableCell> <TableCell>{row.threat_type}</TableCell> <TableCell align="right">{row.anomaly_score?.toFixed(4) ?? 'N/A'}</TableCell> <TableCell>{row.verdict}</TableCell> <TableCell>{row.source_ip}</TableCell> <TableCell>{row.destination_ip ?? 'N/A'}</TableCell> <TableCell align="right">{row.destination_port ?? 'N/A'}</TableCell> <TableCell>{row.protocol ?? 'N/A'}</TableCell> </TableRow> ))) : ( <TableRow><TableCell colSpan={tableColumns.length} align="center">No threats found.</TableCell></TableRow> )} </TableBody> </Table> </TableContainer> <TablePagination rowsPerPageOptions={[10, 25, 50, 100]} component="div" count={tableData?.total || 0} rowsPerPage={pageSize} page={currentPage} onPageChange={handlePageChange} onRowsPerPageChange={handleRowsPerPageChange} /> </Paper>

      <Dialog open={!!selectedThreatId} onClose={handleCloseDetailView} maxWidth="md" fullWidth>
        <DialogTitle sx={{ m: 0, p: 2 }}>
          Threat Detail - ID: {threatDetailData?.id || selectedThreatId}
          <IconButton aria-label="close" onClick={handleCloseDetailView} sx={{ position: 'absolute', right: 8, top: 8, color: (theme) => theme.palette.grey[500] }}>
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {isDetailLoading && <Box sx={{display: 'flex', justifyContent: 'center', my:3}}><CircularProgress /></Box>}
          {detailError && <Alert severity="error">Error loading details: {detailError}</Alert>}
          {threatDetailData && !isDetailLoading && (
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">Timestamp:</Typography>
                <Typography variant="body1">{formatTimestamp(threatDetailData.timestamp)}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Threat Type:</Typography>
                <Typography variant="body1">{threatDetailData.threat_type}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Anomaly Score:</Typography>
                <Typography variant="body1">{threatDetailData.anomaly_score?.toFixed(4) ?? 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Verdict:</Typography>
                <Typography variant="body1">{threatDetailData.verdict}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Description:</Typography>
                <Typography variant="body1" sx={{wordBreak: 'break-word'}}>{threatDetailData.description || 'N/A'}</Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">Source IP:</Typography>
                <Typography variant="body1">{threatDetailData.source_ip}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Destination IP:</Typography>
                <Typography variant="body1">{threatDetailData.destination_ip || 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Destination Port:</Typography>
                <Typography variant="body1">{threatDetailData.destination_port ?? 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Protocol:</Typography>
                <Typography variant="body1">{threatDetailData.protocol || 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Rule ID:</Typography>
                <Typography variant="body1">{threatDetailData.rule_id || 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Category:</Typography>
                <Typography variant="body1">{threatDetailData.category || 'N/A'}</Typography>
                <Typography variant="subtitle2" color="text.secondary" mt={1}>Severity:</Typography>
                <Typography variant="body1">{threatDetailData.severity || 'N/A'}</Typography>
              </Grid>

              {threatDetailData.feature_contributions && threatDetailData.feature_contributions.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom sx={{mt: 2}}>Feature Contributions</Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <RadarChart cx="50%" cy="50%" outerRadius="80%" data={threatDetailData.feature_contributions}>
                      <PolarGrid />
                      <PolarAngleAxis dataKey="feature_name" />
                      <PolarRadiusAxis angle={30} domain={[0, 'auto']} />
                      <Radar name="Contribution" dataKey="value" stroke="#8884d8" fill="#8884d8" fillOpacity={0.6} />
                      <Tooltip />
                      <Legend />
                    </RadarChart>
                  </ResponsiveContainer>
                </Grid>
              )}

              <Grid item xs={12} md={threatDetailData.feature_contributions && threatDetailData.feature_contributions.length > 0 ? 6 : 12}>
                 {renderNestedObject(threatDetailData.flow_metadata, "Flow Metadata")}
              </Grid>


              <Grid item xs={12}>
                 <CardActionArea onClick={handleRawAlertExpandClick} sx={{display: 'flex', justifyContent: 'space-between', p:1}}>
                    <Typography variant="subtitle1">Raw Alert Data</Typography>
                    <ExpandMore expand={rawAlertExpanded} aria-expanded={rawAlertExpanded} aria-label="show more"> <ExpandMoreIcon /> </ExpandMore>
                </CardActionArea>
                <Collapse in={rawAlertExpanded} timeout="auto" unmountOnExit>
                  <Paper variant="outlined" sx={{ p: 1.5, mt: 1, maxHeight: 300, overflow: 'auto' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {JSON.stringify(threatDetailData.raw_alert_data, null, 2)}
                    </pre>
                  </Paper>
                </Collapse>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDetailView}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ThreatAnalysisDashboard;