import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Grid, Typography, Card, CardContent, CircularProgress, Alert, Paper, Chip, Stack, Divider,
  TableContainer, Table, TableHead, TableBody, TableRow, TableCell, TablePagination, TableSortLabel,
  Dialog, DialogTitle, DialogContent, DialogActions, Button, IconButton, List, ListItem, ListItemText, Collapse, CardActionArea,
  TextField, Switch, FormControlLabel // Added Switch and FormControlLabel for compact mode
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { styled, useTheme } from '@mui/material/styles'; // Imported useTheme
import { AlertTriangle, Smile, Frown, TrendingUp, Tags as TagsIcon, MapPin, Filter as FilterIcon, Settings2 } from 'lucide-react'; // Added MapPin, FilterIcon, Settings2
import CountUp from 'react-countup';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';

// --- Types/Interfaces ---
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

interface AnomalyTopPattern {
  type: string;
  count: number;
}

interface AnomalySummaryData {
  total_anomaly_alerts: number;
  benign_percentage: number;
  malicious_percentage: number;
  average_anomaly_score_24h?: number | null;
  retraining_last_occurred?: string | null;
  top_3_anomaly_patterns: AnomalyTopPattern[];
}

interface AnomalyTrendPoint {
  time_bucket: string;
  count: number;
}

interface AnomalyScoreHeatmapPoint {
  time_bucket: string;
  score_range: string;
  count: number;
}

interface AnomalyOriginPoint {
  country: string;
  count: number;
}

interface AnomalyTrendsData {
  threats_over_time: AnomalyTrendPoint[];
  anomaly_score_heatmap_data: AnomalyScoreHeatmapPoint[];
  threat_origins: AnomalyOriginPoint[];
}

interface AnomalyTableRow {
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

interface PaginatedAnomalyTableResponse {
  total: number;
  items: AnomalyTableRow[];
  page: number;
  size: number;
  pages: number;
}

interface AnomalyFlowFeature {
  feature_name: string;
  value: number;
}

interface AnomalyFlowMetadataDetail {
  packet_counts?: { [key: string]: number } | null;
  duration_seconds?: number | null;
  flags_summary?: { [key: string]: number } | null;
  active_idle_stats?: { [key: string]: number } | null;
  payload_length_stats?: { [key: string]: number } | null;
  raw_features?: { [key: string]: any } | null;
}

interface AnomalyDetailResponse extends AnomalyTableRow {
  description?: string | null;
  rule_id?: string | null;
  category?: string | null;
  severity?: string | null;
  feature_contributions?: AnomalyFlowFeature[] | null;
  flow_metadata?: AnomalyFlowMetadataDetail | null;
  raw_alert_data?: { [key: string]: any } | null;
}

type SortDirection = 'asc' | 'desc';

interface SortConfig {
  key: string;
  direction: SortDirection;
}

// --- API Client Functions ---
const ANOMALY_THREAT_TYPE_FILTER = "Anomaly";

async function fetchAnomalySummary(): Promise<AnomalySummaryData> {
  const response = await fetch(`/api/v1/threat-analysis/summary?threat_type=${ANOMALY_THREAT_TYPE_FILTER}`);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch anomaly summary: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    const data = await response.json();
    return {
      total_anomaly_alerts: data.total_threats,
      benign_percentage: data.benign_percentage,
      malicious_percentage: data.malicious_percentage,
      average_anomaly_score_24h: data.average_anomaly_score_24h,
      retraining_last_occurred: data.retraining_last_occurred,
      top_3_anomaly_patterns: data.top_3_attack_types.map((item: any) => ({ type: item.type, count: item.count })),
    };
  } catch (e) {
    console.error("Error parsing anomaly summary response:", e);
    throw new Error(`Failed to parse anomaly summary response: ${e instanceof Error ? e.message : String(e)}`);
  }
}

async function fetchAnomalyTrends(): Promise<AnomalyTrendsData> {
  const response = await fetch(`/api/v1/threat-analysis/trends?threat_type=${ANOMALY_THREAT_TYPE_FILTER}`);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch anomaly trends: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    const data = await response.json();
    return {
      threats_over_time: data.threats_over_time || [],
      anomaly_score_heatmap_data: data.anomaly_score_heatmap_data || [],
      threat_origins: data.threat_origins || [],
    };
  } catch (e) {
    console.error("Error parsing anomaly trends response:", e);
    throw new Error(`Failed to parse anomaly trends response: ${e instanceof Error ? e.message : String(e)}`);
  }
}

async function fetchAnomalyTable(
  page: number,
  size: number,
  sortBy?: string,
  sortDesc?: boolean,
): Promise<PaginatedAnomalyTableResponse> {
  const params = new URLSearchParams({
    page: String(page),
    size: String(size),
    threat_type: ANOMALY_THREAT_TYPE_FILTER,
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
    throw new Error(`Failed to fetch anomaly table: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse anomaly table response: ${e instanceof Error ? e.message : String(e)}`);
  }
}

async function fetchAnomalyDetail(threatId: string): Promise<AnomalyDetailResponse> {
  const response = await fetch(`/api/v1/threat-analysis/threats/${threatId}`);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to fetch anomaly detail for ID ${threatId}: ${response.status} ${response.statusText} - ${errorBody}`);
  }
  try {
    return await response.json();
  } catch (e) {
    throw new Error(`Failed to parse anomaly detail response: ${e instanceof Error ? e.message : String(e)}`);
  }
}


const AnomalyInsightsSection: React.FC = () => {
  const theme = useTheme(); // For accessing theme properties

  const [summaryData, setSummaryData] = useState<AnomalySummaryData | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState<boolean>(true);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [trendsData, setTrendsData] = useState<AnomalyTrendsData | null>(null);
  const [isLoadingTrends, setIsLoadingTrends] = useState<boolean>(true);
  const [trendsError, setTrendsError] = useState<string | null>(null);

  const [anomalyTableData, setAnomalyTableData] = useState<PaginatedAnomalyTableResponse | null>(null);
  const [isTableLoading, setIsTableLoading] = useState<boolean>(true);
  const [tableError, setTableError] = useState<string | null>(null);
  const [currentTablePage, setCurrentTablePage] = useState<number>(0);
  const [tablePageSize, setTablePageSize] = useState<number>(10);
  const [tableSortConfig, setTableSortConfig] = useState<SortConfig>({ key: 'timestamp', direction: 'desc' });

  const [selectedAnomalyId, setSelectedAnomalyId] = useState<string | null>(null);
  const [anomalyDetailData, setAnomalyDetailData] = useState<AnomalyDetailResponse | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState<boolean>(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [rawAlertExpanded, setRawAlertExpanded] = useState(false);

  const [isCompactMode, setIsCompactMode] = useState(false);


  const loadAnomalyTableData = useCallback(async () => {
    setIsTableLoading(true);
    setTableError(null);
    try {
      const data = await fetchAnomalyTable(
        currentTablePage + 1,
        tablePageSize,
        tableSortConfig.key,
        tableSortConfig.direction === 'desc'
      );
      setAnomalyTableData(data);
    } catch (err) {
      console.error("Error loading anomaly table data:", err);
      setTableError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsTableLoading(false);
    }
  }, [currentTablePage, tablePageSize, tableSortConfig]);

  useEffect(() => {
    const loadInitialPageData = async () => {
      setIsLoadingSummary(true);
      setIsLoadingTrends(true);
      setIsTableLoading(true);

      const results = await Promise.allSettled([
        fetchAnomalySummary(),
        fetchAnomalyTrends(),
        fetchAnomalyTable(1, tablePageSize, tableSortConfig.key, tableSortConfig.direction === 'desc'),
      ]);

      if (results[0].status === 'fulfilled') setSummaryData(results[0].value as AnomalySummaryData);
      else setSummaryError(results[0].reason instanceof Error ? results[0].reason.message : 'Unknown summary error');
      setIsLoadingSummary(false);

      if (results[1].status === 'fulfilled') setTrendsData(results[1].value as AnomalyTrendsData);
      else setTrendsError(results[1].reason instanceof Error ? results[1].reason.message : 'Unknown trends error');
      setIsLoadingTrends(false);

      if (results[2].status === 'fulfilled') setAnomalyTableData(results[2].value as PaginatedAnomalyTableResponse);
      else setTableError(results[2].reason instanceof Error ? results[2].reason.message : 'Unknown table error');
      setIsTableLoading(false);
    };
    loadInitialPageData();
  }, []);

  useEffect(() => {
    if(!isLoadingSummary && !isLoadingTrends && !isTableLoading) {
       loadAnomalyTableData();
    }
  }, [currentTablePage, tablePageSize, tableSortConfig, isLoadingSummary, isLoadingTrends, loadAnomalyTableData]);


  const loadAnomalyDetail = useCallback(async (threatId: string) => {
    setIsDetailLoading(true);
    setDetailError(null);
    setAnomalyDetailData(null);
    try {
      const data = await fetchAnomalyDetail(threatId);
      setAnomalyDetailData(data);
    } catch (err) {
      console.error(`Error loading anomaly detail for ID ${threatId}:`, err);
      setDetailError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsDetailLoading(false);
    }
  }, []);

  const handleTableSortRequest = (propertyKey: string) => {
    const isAsc = tableSortConfig.key === propertyKey && tableSortConfig.direction === 'asc';
    setTableSortConfig({ key: propertyKey, direction: isAsc ? 'desc' : 'asc' });
    setCurrentTablePage(0);
  };

  const handleTablePageChange = (event: unknown, newPage: number) => {
    setCurrentTablePage(newPage);
  };

  const handleTableRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setTablePageSize(parseInt(event.target.value, 10));
    setCurrentTablePage(0);
  };

  const handleTableRowClick = (anomalyId: string) => {
    if (selectedAnomalyId === anomalyId) {
      setSelectedAnomalyId(null);
      setAnomalyDetailData(null);
      setDetailError(null);
    } else {
      setSelectedAnomalyId(anomalyId);
      loadAnomalyDetail(anomalyId);
    }
  };

  const handleCloseDetailDialog = () => {
    setSelectedAnomalyId(null);
    setAnomalyDetailData(null);
    setDetailError(null);
    setRawAlertExpanded(false);
  };

  const handleRawAlertExpandClick = () => {
    setRawAlertExpanded(!rawAlertExpanded);
  };

  const handleCompactModeToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    setIsCompactMode(event.target.checked);
  };

  const formatTimestamp = (isoString: string | undefined | null): string => {
    if (!isoString) return 'N/A';
    try { return new Date(isoString).toLocaleString(); }
    catch (e) { return isoString; }
  };

  const formatDateTick = (tickItem: string) => {
    try {
      const date = new Date(tickItem);
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ', ' + date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch (e) { return tickItem; }
  };

  const aggregatedScoreDistribution = trendsData?.anomaly_score_heatmap_data.reduce((acc, item) => {
    const existing = acc.find(d => d.score_range === item.score_range);
    if (existing) existing.count += item.count;
    else acc.push({ score_range: item.score_range, count: item.count });
    return acc;
  }, [] as { score_range: string; count: number }[]).sort((a,b) => parseFloat(a.score_range.split('-')[0]) - parseFloat(b.score_range.split('-')[0]));

  const anomalyTableColumns: { id: keyof AnomalyTableRow | 'actions'; label: string; minWidth?: number; numeric?: boolean; sortable?: boolean }[] = [
    { id: 'timestamp', label: 'Timestamp', minWidth: 170, sortable: true }, { id: 'threat_type', label: 'Anomaly Type', minWidth: 150, sortable: false }, { id: 'anomaly_score', label: 'Score', minWidth: 80, numeric: true, sortable: true }, { id: 'verdict', label: 'Verdict', minWidth: 100, sortable: true }, { id: 'source_ip', label: 'Source IP', minWidth: 120, sortable: true }, { id: 'destination_ip', label: 'Dest. IP', minWidth: 120, sortable: true }, { id: 'destination_port', label: 'Dest. Port', minWidth: 100, numeric: true, sortable: true }, { id: 'protocol', label: 'Protocol', minWidth: 80, sortable: true },
  ];

  const getVerdictChipColor = (verdict: string): "success" | "error" | "warning" | "default" => {
    const lowerVerdict = verdict.toLowerCase();
    if (lowerVerdict === "benign") return "success";
    if (lowerVerdict === "malicious") return "error";
    if (lowerVerdict === "suspicious") return "warning";
    return "default";
  };

  const renderDetailItem = (label: string, value: string | number | undefined | null) => (
    value !== null && value !== undefined && String(value).trim() !== '' && String(value) !== 'N/A' ? (
      <ListItem dense sx={{py: 0.25}}>
        <ListItemText primaryTypographyProps={{variant: 'body2'}} secondaryTypographyProps={{variant: 'caption'}} primary={String(value)} secondary={label} />
      </ListItem>
    ) : null
  );

  const renderNestedObject = (obj: { [key: string]: any } | null | undefined, title: string) => {
    if (!obj || Object.keys(obj).length === 0) return <Typography variant="body2" sx={{mt:1, fontStyle: 'italic'}}>{title}: N/A</Typography>;
    return (
      <Box mt={2}>
        <Typography variant="subtitle1" gutterBottom sx={{fontWeight:'medium'}}>{title}</Typography>
        <Paper variant="outlined" sx={{ p: 1.5, maxHeight: 150, overflow: 'auto', backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.03)' }}>
          <List dense>
            {Object.entries(obj).map(([key, value]) => renderDetailItem(key, String(value)))}
          </List>
        </Paper>
      </Box>
    );
  };

  const summaryCardHoverSx = { '&:hover': { transform: 'scale(1.03)', boxShadow: theme.shadows[10] }, transition: 'transform 0.15s ease-in-out, box-shadow 0.15s ease-in-out' };
  const tableRowHoverSx = { cursor: 'pointer', '&:hover': { backgroundColor: theme.palette.action.hover }};


  return (
    <Paper elevation={3} sx={{ p: { xs: 2, md: 3 }, mt: 2, backgroundColor: 'background.paper' }}>
      <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2}}>
        <Typography variant="h5" component="h2" gutterBottom sx={{ mb: 0 }}>Anomaly Insights</Typography>
        <FormControlLabel
          control={<Switch checked={isCompactMode} onChange={handleCompactModeToggle} size="small" />}
          label="Compact Mode"
          sx={{color: 'text.secondary'}}
        />
      </Box>

      {isLoadingSummary ? <Box sx={{display:'flex', justifyContent:'center', my:2}}><CircularProgress size={24}/> <Typography sx={{ml:1}}>Loading summary...</Typography></Box> : summaryError ? <Alert severity="error" sx={{mb:2}}>Summary: {summaryError}</Alert> : !summaryData ? <Alert severity="info" sx={{mb:2}}>No Summary data.</Alert> :
        <Grid container spacing={isCompactMode ? 2 : 3} sx={{mb: 3}}>
          <Grid item xs={12} sm={6} md={isCompactMode ? 2.4 : 3}>
            <Card sx={{ height: '100%', ...summaryCardHoverSx }}>
              <CardContent sx={{ textAlign: 'center', p: isCompactMode ? 1.5 : 2, '& .lucide': {mb: isCompactMode ? 0.5 : 1 } }}>
                <AlertTriangle size={isCompactMode ? 28 : 36} color={theme.palette.warning.main} />
                <Typography variant={isCompactMode ? "subtitle1" : "h6"} color="text.secondary" gutterBottom> Total Anomalies </Typography>
                <Typography variant={isCompactMode ? "h5" : "h3"} component="div" sx={{ fontWeight: 'bold' }}> <CountUp end={summaryData.total_anomaly_alerts} duration={2.5} separator="," /> </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={isCompactMode ? 2.4 : 3}>
            <Card sx={{ height: '100%', ...summaryCardHoverSx }}>
              <CardContent sx={{p: isCompactMode ? 1.5 : 2, '& .lucide': {mr:1 }}}>
                <Typography variant={isCompactMode ? "subtitle1" : "h6"} color="text.secondary" gutterBottom sx={{ textAlign: 'center' }}> Anomaly Verdicts </Typography>
                <Box display="flex" alignItems="center" my={isCompactMode ? 0.5 : 1}> <Smile size={isCompactMode ? 20 : 24} color={theme.palette.success.main} /> <Typography variant={isCompactMode ? "body1" : "h6"} component="span" sx={{ color: theme.palette.success.main, fontWeight: 'medium' }}> Benign: <CountUp end={summaryData.benign_percentage} duration={2.5} decimals={2} suffix="%" /> </Typography> </Box>
                <Box display="flex" alignItems="center" my={isCompactMode ? 0.5 : 1}> <Frown size={isCompactMode ? 20 : 24} color={theme.palette.error.main} /> <Typography variant={isCompactMode ? "body1" : "h6"} component="span" sx={{ color: theme.palette.error.main, fontWeight: 'medium' }}> Malicious: <CountUp end={summaryData.malicious_percentage} duration={2.5} decimals={2} suffix="%" /> </Typography> </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={isCompactMode ? 2.4 : 3}>
            <Card sx={{ height: '100%', ...summaryCardHoverSx, ...(summaryData.average_anomaly_score_24h && summaryData.average_anomaly_score_24h > 0.9 && { boxShadow: (theme) => `${theme.shadows[8]}, 0 0 15px 4px ${theme.palette.warning.light}`, borderColor: theme.palette.warning.main }) }}>
              <CardContent sx={{ textAlign: 'center', p: isCompactMode ? 1.5 : 2, '& .lucide': {mb: isCompactMode ? 0.5 : 1 } }}>
                <TrendingUp size={isCompactMode ? 28 : 36} color={theme.palette.info.main} />
                <Typography variant={isCompactMode ? "subtitle1" : "h6"} color="text.secondary" gutterBottom> Avg. Score (24h) </Typography>
                <Typography variant={isCompactMode ? "h5" : "h3"} component="div" sx={{ fontWeight: 'bold' }}> {summaryData.average_anomaly_score_24h !== null && summaryData.average_anomaly_score_24h !== undefined ? <CountUp end={summaryData.average_anomaly_score_24h} duration={2.5} decimals={4} /> : 'N/A'} </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={isCompactMode ? 2.4 : 3}>
            <Card sx={{ height: '100%', ...summaryCardHoverSx }}>
              <CardContent sx={{p: isCompactMode ? 1.5 : 2, '& .lucide': {mr:1 }}}>
                <Box display="flex" alignItems="center" mb={isCompactMode ? 0.5 : 1}> <TagsIcon size={isCompactMode ? 20 : 24} color={theme.palette.secondary.main} /> <Typography variant={isCompactMode ? "subtitle1" : "h6"} color="text.secondary"> Top Patterns </Typography> </Box>
                {summaryData.top_3_anomaly_patterns.length > 0 ? ( <Stack spacing={isCompactMode ? 0.5 : 1} mt={isCompactMode ? 0.5 : 1}> {summaryData.top_3_anomaly_patterns.map((pattern, index) => ( <Chip key={index} label={`${pattern.type}: ${pattern.count.toLocaleString()}`} variant="outlined" size={isCompactMode ? "small" : "medium"} /> ))} </Stack> ) : ( <Typography variant="body2" sx={{textAlign: 'center', mt:2}}>No patterns.</Typography> )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      }

      <Divider sx={{my: 3}} />

      {/* Filter Placeholders */}
      <Paper elevation={0} variant="outlined" sx={{ mb: 3, p: 2}}>
        <Grid container spacing={2} alignItems="center">
          <Grid item><FilterIcon size={18} style={{color: theme.palette.text.secondary}} /></Grid>
          <Grid item><Typography variant="subtitle1" color="text.secondary">Filters:</Typography></Grid>
          <Grid item xs={12} sm="auto"> <Button variant="outlined" size="small" disabled>Last 1hr</Button> </Grid>
          <Grid item xs={12} sm="auto"> <Button variant="outlined" size="small" disabled>Last 24hrs</Button> </Grid>
          <Grid item xs={12} sm="auto"> <Button variant="outlined" size="small" disabled>Last 7 Days</Button> </Grid>
          <Grid item xs={12} sm={6} md={2}> <TextField label="Start Date" size="small" type="date" InputLabelProps={{ shrink: true }} disabled fullWidth variant="standard"/> </Grid>
          <Grid item xs={12} sm={6} md={2}> <TextField label="End Date" size="small" type="date" InputLabelProps={{ shrink: true }} disabled fullWidth variant="standard"/> </Grid>
          <Grid item xs={12} sm={6} md={2}> <TextField label="Source IP" size="small" disabled fullWidth variant="standard"/> </Grid>
          <Grid item xs={6} sm={3} md={1}> <TextField label="Min Score" size="small" type="number" disabled fullWidth variant="standard"/> </Grid>
          <Grid item xs={6} sm={3} md={1}> <TextField label="Max Score" size="small" type="number" disabled fullWidth variant="standard"/> </Grid>
          <Grid item xs={12} sm="auto"> <Button variant="contained" size="small" disabled>Apply</Button> </Grid>
        </Grid>
      </Paper>

      <Typography variant="h6" component="h3" gutterBottom sx={{ mb: 2 }}>Anomaly Trends</Typography>
      {isLoadingTrends ? <Box sx={{display:'flex', justifyContent:'center', my:2}}><CircularProgress size={24}/> <Typography sx={{ml:1}}>Loading trends...</Typography></Box> : trendsError ? <Alert severity="error" sx={{mb:2}}>Trends: {trendsError}</Alert> : !trendsData || (trendsData.threats_over_time.length === 0 && trendsData.anomaly_score_heatmap_data.length === 0 && (!trendsData.threat_origins || trendsData.threat_origins.length === 0)) ? <Alert severity="info" sx={{mb:2}}>No anomaly trend data.</Alert> :
        <Grid container spacing={3} sx={{mb:4}}>
          <Grid item xs={12} md={4}> <Card sx={{height:'100%', ...summaryCardHoverSx}}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Alerts Over Time</Typography> {trendsData.threats_over_time?.length > 0 ? (<ResponsiveContainer width="100%" height={230}> <LineChart data={trendsData.threats_over_time}> <CartesianGrid strokeDasharray="3 3" /> <XAxis dataKey="time_bucket" tickFormatter={formatDateTick} angle={-20} textAnchor="end" height={50}/> <YAxis allowDecimals={false}/> <Tooltip labelFormatter={(label) => formatDateTick(label)}/> <Legend /> <Line type="monotone" dataKey="count" name="Anomalies" stroke={theme.palette.primary.main} strokeWidth={2}/> </LineChart> </ResponsiveContainer>) : (<Typography variant="body2" align="center" sx={{py:3}}>No time-series data.</Typography>)} </CardContent> </Card> </Grid>
          {aggregatedScoreDistribution && aggregatedScoreDistribution.length > 0 && (
            <Grid item xs={12} md={4}> <Card sx={{height:'100%', ...summaryCardHoverSx}}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Score Distribution</Typography> <ResponsiveContainer width="100%" height={230}> <BarChart data={aggregatedScoreDistribution}> <CartesianGrid strokeDasharray="3 3" /> <XAxis dataKey="score_range"/> <YAxis allowDecimals={false}/> <Tooltip /> <Legend /> <Bar dataKey="count" fill={theme.palette.success.main} name="Count"/> </BarChart> </ResponsiveContainer> </CardContent> </Card> </Grid>
          )}
          {trendsData.threat_origins && trendsData.threat_origins.length > 0 && (
             <Grid item xs={12} md={4}>
                <Card sx={{height:'100%', ...summaryCardHoverSx}}> <CardContent> <Typography variant="subtitle1" color="text.secondary" gutterBottom>Top Anomaly Origins</Typography> <ResponsiveContainer width="100%" height={230}> <BarChart data={trendsData.threat_origins} layout="vertical"> <CartesianGrid strokeDasharray="3 3" /> <XAxis type="number" allowDecimals={false}/> <YAxis type="category" dataKey="country" width={80} tick={{fontSize:12}}/> <Tooltip /> <Legend /> <Bar dataKey="count" fill={theme.palette.warning.main} name="Count"/> </BarChart> </ResponsiveContainer> </CardContent> </Card>
             </Grid>
          )}
        </Grid>
      }

      <Divider sx={{my: 3}} />
      <Typography variant="h6" component="h3" gutterBottom sx={{ mb: 2 }}>Anomaly Alerts Log</Typography>
      {isTableLoading && !anomalyTableData?.items?.length && <Box sx={{display:'flex', justifyContent:'center', my:2}}><CircularProgress/></Box>}
      {tableError && <Alert severity="error" sx={{mb:2}}>Failed to load anomaly logs: {tableError}</Alert>}
      {!isTableLoading && !anomalyTableData?.items?.length && !tableError && <Alert severity="info" sx={{mb:2}}>No anomaly logs found.</Alert>}
      {anomalyTableData?.items && anomalyTableData.items.length > 0 && (
         <Paper sx={{ width: '100%', overflow: 'hidden', mt: 2 }}>
         <TableContainer sx={{ maxHeight: 500 }}>
           <Table stickyHeader aria-label="anomaly log table">
             <TableHead> <TableRow> {anomalyTableColumns.map((c) => ( <TableCell key={c.id} align={c.numeric ? 'right' : 'left'} style={{ minWidth: c.minWidth }} sortDirection={c.sortable && tableSortConfig.key === c.id ? tableSortConfig.direction : false} sx={{py: isCompactMode ? 0.5 : 1.5}}> {c.sortable ? (<TableSortLabel active={tableSortConfig.key === c.id} direction={tableSortConfig.key === c.id ? tableSortConfig.direction : 'asc'} onClick={() => c.id !== 'actions' && handleTableSortRequest(c.id)}> {c.label} </TableSortLabel>) : ( c.label )} </TableCell> ))} </TableRow> </TableHead>
             <TableBody> {anomalyTableData.items.map((row) => ( <TableRow hover key={row.id} onClick={() => handleTableRowClick(row.id)} selected={selectedAnomalyId === row.id} sx={{...tableRowHoverSx, py: isCompactMode ? 0.25 : 1}}> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}>{formatTimestamp(row.timestamp)}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}>{row.threat_type}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}} align="right">{row.anomaly_score?.toFixed(4) ?? 'N/A'}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}><Chip label={row.verdict} color={getVerdictChipColor(row.verdict)} size="small" /></TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}>{row.source_ip}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}>{row.destination_ip ?? 'N/A'}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}} align="right">{row.destination_port ?? 'N/A'}</TableCell> <TableCell sx={{py: isCompactMode ? 0.5 : 1}}>{row.protocol ?? 'N/A'}</TableCell> </TableRow> ))} </TableBody>
           </Table>
         </TableContainer>
         <TablePagination rowsPerPageOptions={[10, 25, 50]} component="div" count={anomalyTableData.total || 0} rowsPerPage={tablePageSize} page={currentTablePage} onPageChange={handleTablePageChange} onRowsPerPageChange={handleTableRowsPerPageChange} />
       </Paper>
      )}

      <Dialog open={!!selectedAnomalyId} onClose={handleCloseDetailDialog} maxWidth="lg" fullWidth PaperProps={{sx: {bgcolor: 'background.default'}}}>
        <DialogTitle sx={{ m: 0, p: 2, bgcolor: 'background.paper' }}> Anomaly Details - ID: {anomalyDetailData?.id || selectedAnomalyId} <IconButton aria-label="close" onClick={handleCloseDetailDialog} sx={{ position: 'absolute', right: 8, top: 8, color: (theme) => theme.palette.grey[500] }}> <CloseIcon /> </IconButton> </DialogTitle>
        <DialogContent dividers sx={{bgcolor: 'background.paper', p: isCompactMode? 1.5 : 3}}>
          {isDetailLoading && <Box sx={{display: 'flex', justifyContent: 'center', my:3}}><CircularProgress /></Box>}
          {detailError && <Alert severity="error">Error loading details: {detailError}</Alert>}
          {anomalyDetailData && !isDetailLoading && (
            <Grid container spacing={isCompactMode ? 2 : 3} mt={0.5}>
              <Grid item xs={12} md={4}> <Paper elevation={2} sx={{p:2, height:'100%'}}> <Typography variant="h6" gutterBottom>Overview</Typography> {/* Basic Info ListItems */} </Paper> </Grid>
              <Grid item xs={12} md={8}>
                {anomalyDetailData.feature_contributions && anomalyDetailData.feature_contributions.length > 0 && (
                  <Paper elevation={2} sx={{p:2, mb:2}}> <Typography variant="h6" gutterBottom>Feature Contributions</Typography> <ResponsiveContainer width="100%" height={300}> <RadarChart data={anomalyDetailData.feature_contributions}> <PolarGrid /> <PolarAngleAxis dataKey="feature_name" tick={{ fontSize: 10 }} /> <PolarRadiusAxis angle={30} domain={[0, 'auto']} /> <Radar name="Contribution" dataKey="value" stroke={theme.palette.primary.main} fill={theme.palette.primary.main} fillOpacity={0.6} /> <Tooltip /> <Legend /> </RadarChart> </ResponsiveContainer> </Paper>
                )}
                {renderNestedObject(anomalyDetailData.flow_metadata, "Flow Metadata")}
              </Grid>
              <Grid item xs={12}> <Card elevation={2}> <CardActionArea onClick={handleRawAlertExpandClick} sx={{display: 'flex', justifyContent: 'space-between', p:1.5}}> <Typography variant="subtitle1" sx={{fontWeight:'medium'}}>Raw Alert Data</Typography> <ExpandMore expand={rawAlertExpanded} aria-expanded={rawAlertExpanded} aria-label="show more raw data"> <ExpandMoreIcon /> </ExpandMore> </CardActionArea> <Collapse in={rawAlertExpanded} timeout="auto" unmountOnExit> <CardContent sx={{borderTop: '1px solid', borderColor:'divider'}}> <Paper variant="outlined" sx={{ p: 1.5, mt: 1, maxHeight: 300, overflow: 'auto', backgroundColor: theme.palette.mode === 'dark' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.05)'}}> <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.8rem' }}> {JSON.stringify(anomalyDetailData.raw_alert_data, null, 2)} </pre> </Paper> </CardContent> </Collapse> </Card> </Grid>
              <Grid item xs={12}>
                <Box sx={{mt:2, display: 'flex', gap: 1, borderTop: '1px solid', borderColor: 'divider', pt: 2}}>
                  <Button variant="outlined" disabled>Flag for Investigation</Button>
                  <Button variant="outlined" color="secondary" disabled>Mark as False Positive</Button>
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions sx={{bgcolor: 'background.paper'}}> <Button onClick={handleCloseDetailDialog}>Close</Button> </DialogActions>
      </Dialog>
    </Paper>
  );
};

export default AnomalyInsightsSection;