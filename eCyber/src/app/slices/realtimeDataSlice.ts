// This file will contain Redux slices for real-time data.
import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import {
  // DnsQuery, // Original, replaced by DnsActivityData
  DnsActivityData, // Updated type
  // FirewallEvent, // Original, replaced by FirewallActivityData
  FirewallActivityData, // Updated type
  Alert, // Refined in usePacketSnifferSocket.ts
  IPv6Activity, // Refined
  PacketMetadata, // Refined (e.g., added id, payload_preview)
  SystemStats,    // Refined
  SystemStatus,   // Refined
  PhishingData,   // Refined
  ThreatResponse, // Refined
  FileQuarantined,// Refined
} from '../../hooks/usePacketSnifferSocket'; 

import { clearOldPacketBytes } from '@/lib/clearOldPacketBytes'

// --- DNS Activities Slice ---
interface DnsActivityState {
  dnsActivities: DnsActivityData[]; // Use updated DnsActivityData
}

const initialDnsActivityState: DnsActivityState = {
  dnsActivities: [],
};

const dnsActivitySlice = createSlice({
  name: 'dnsActivity',
  initialState: initialDnsActivityState,
  reducers: {
    addDnsActivity: (state, action: PayloadAction<DnsActivityData>) => { // Use DnsActivityData
      state.dnsActivities = [action.payload, ...state.dnsActivities].slice(0, 100);
    },
  },
});

export const { addDnsActivity } = dnsActivitySlice.actions;
export const dnsActivityReducer = dnsActivitySlice.reducer;

// --- Firewall Events Slice ---
interface FirewallEventsState {
  firewallEventsData: FirewallActivityData[]; // Use updated FirewallActivityData
}

const initialFirewallEventsState: FirewallEventsState = {
  firewallEventsData: [],
};

const firewallEventsSlice = createSlice({
  name: 'firewallEvents',
  initialState: initialFirewallEventsState,
  reducers: {
    addFirewallEvent: (state, action: PayloadAction<FirewallActivityData>) => { // Use FirewallActivityData
      state.firewallEventsData = [action.payload, ...state.firewallEventsData].slice(0, 100);
    },
  },
});

export const { addFirewallEvent } = firewallEventsSlice.actions;
export const firewallEventsReducer = firewallEventsSlice.reducer;

// --- Threat Detections Slice ---
// Uses refined Alert type
interface ThreatDetectionsState {
  threatDetectionsData: Alert[]; 
}

const initialThreatDetectionsState: ThreatDetectionsState = {
  threatDetectionsData: [],
};

const threatDetectionsSlice = createSlice({
  name: 'threatDetections',
  initialState: initialThreatDetectionsState,
  reducers: {
    addThreatDetection: (state, action: PayloadAction<Alert>) => {
      state.threatDetectionsData = [action.payload, ...state.threatDetectionsData].slice(0, 100);
    },
  },
});

export const { addThreatDetection } = threatDetectionsSlice.actions;
export const threatDetectionsReducer = threatDetectionsSlice.reducer;

// --- IPv6 Activities Slice ---
interface IPv6ActivityState {
  ipv6ActivitiesData: IPv6Activity[];
}

const initialIPv6ActivityState: IPv6ActivityState = {
  ipv6ActivitiesData: [],
};

const ipv6ActivitySlice = createSlice({
  name: 'ipv6Activity',
  initialState: initialIPv6ActivityState,
  reducers: {
    addIPv6Activity: (state, action: PayloadAction<IPv6Activity>) => {
      state.ipv6ActivitiesData = [action.payload, ...state.ipv6ActivitiesData].slice(0, 100);
    },
  },
});

export const { addIPv6Activity } = ipv6ActivitySlice.actions;
export const ipv6ActivityReducer = ipv6ActivitySlice.reducer;

// --- Packet Data Slice ---
interface PacketDataState {
  packetEntries: PacketMetadata[];
}

const initialPacketDataState: PacketDataState = {
  packetEntries: [],
};

const packetDataSlice = createSlice({
  name: 'packetData',
  initialState: initialPacketDataState,
  reducers: {
    addPacketEntry: (state, action: PayloadAction<PacketMetadata>) => {
      state.packetEntries = [action.payload, ...state.packetEntries].slice(0, 200);
    },
  },
});

export const { addPacketEntry } = packetDataSlice.actions;
export const packetDataReducer = packetDataSlice.reducer;

// --- System Metrics Slice ---
interface SystemMetricsState {
  systemStats: SystemStats | null;
  systemStatus: SystemStatus | null;
}

const initialSystemMetricsState: SystemMetricsState = {
  systemStats: null,
  systemStatus: null,
};

const systemMetricsSlice = createSlice({
  name: 'systemMetrics',
  initialState: initialSystemMetricsState,
  reducers: {
    updateSystemStats: (state, action: PayloadAction<SystemStats>) => {
      state.systemStats = action.payload;
    },
    updateSystemStatus: (state, action: PayloadAction<SystemStatus>) => {
      state.systemStatus = action.payload;
    },
  },
});

export const { updateSystemStats, updateSystemStatus } = systemMetricsSlice.actions;
export const systemMetricsReducer = systemMetricsSlice.reducer;

// --- General Security Alerts Slice ---
interface SecurityAlertsState {
  recentAlerts: Alert[];
}

const initialSecurityAlertsState: SecurityAlertsState = {
  recentAlerts: [],
};

const securityAlertsSlice = createSlice({
  name: 'securityAlerts',
  initialState: initialSecurityAlertsState,
  reducers: {
    addSecurityAlert: (state, action: PayloadAction<Alert>) => {
      state.recentAlerts = [action.payload, ...state.recentAlerts].slice(0, 50);
    },
  },
});

export const { addSecurityAlert } = securityAlertsSlice.actions;
export const securityAlertsReducer = securityAlertsSlice.reducer;

// --- Phishing Detections Slice ---
interface PhishingDetectionsState {
  phishingDetectionsData: PhishingData[];
}

const initialPhishingDetectionsState: PhishingDetectionsState = {
  phishingDetectionsData: [],
};

const phishingDetectionsSlice = createSlice({
  name: 'phishingDetections',
  initialState: initialPhishingDetectionsState,
  reducers: {
    addPhishingDetection: (state, action: PayloadAction<PhishingData>) => {
      state.phishingDetectionsData = [action.payload, ...state.phishingDetectionsData].slice(0, 100);
    },
  },
});

export const { addPhishingDetection } = phishingDetectionsSlice.actions;
export const phishingDetectionsReducer = phishingDetectionsSlice.reducer;

// --- Threat Responses Slice ---
interface ThreatResponsesState {
  threatResponsesData: ThreatResponse[];
}

const initialThreatResponsesState: ThreatResponsesState = {
  threatResponsesData: [],
};

const threatResponsesSlice = createSlice({
  name: 'threatResponses',
  initialState: initialThreatResponsesState,
  reducers: {
    addThreatResponse: (state, action: PayloadAction<ThreatResponse>) => {
      state.threatResponsesData = [action.payload, ...state.threatResponsesData].slice(0, 100);
    },
  },
});


clearOldPacketBytes(); // 🔁 Ensure it's called before accessing localStorage

const initialVolume = Number(localStorage.getItem('packet_bytes')) || 0;

const networkVolume = createSlice({
  name: 'networkVolume',
  initialState: {
    networkVolume: initialVolume
  },
  reducers: {
    addNetworkVolume: (state, action) => {
      state.networkVolume += action.payload;
      localStorage.setItem('packet_bytes', JSON.stringify(state.networkVolume));
    }
  }
});

const initialInterfaces = JSON.parse(localStorage.getItem('interfaces')) || [];

const networkInterfaces = createSlice({
  name: 'networkInterfaces',
  initialState: {
    networkInterfaces: initialInterfaces
  },
  reducers: {
    getNetworkInterfaces: (state, action) => {
      state.networkInterfaces = action.payload;
      localStorage.setItem('networkInterfaces', JSON.stringify(state.networkInterfaces));
    }
  }
});



export const { addNetworkVolume } = networkVolume.actions
export const networkVolumeReducer = networkVolume.reducer
export const { getNetworkInterfaces } = networkInterfaces.actions
export const networkInterfaceReducer = networkInterfaces.reducer
export const { addThreatResponse } = threatResponsesSlice.actions;
export const threatResponsesReducer = threatResponsesSlice.reducer;

// --- Quarantined Files Slice ---
interface QuarantinedFilesState {
  quarantinedFilesData: FileQuarantined[];
}

const initialQuarantinedFilesState: QuarantinedFilesState = {
  quarantinedFilesData: [],
};

const quarantinedFilesSlice = createSlice({
  name: 'quarantinedFiles',
  initialState: initialQuarantinedFilesState,
  reducers: {
    addQuarantinedFile: (state, action: PayloadAction<FileQuarantined>) => {
      state.quarantinedFilesData = [action.payload, ...state.quarantinedFilesData].slice(0, 100);
    },
  },
});

export const { addQuarantinedFile } = quarantinedFilesSlice.actions;
export const quarantinedFilesReducer = quarantinedFilesSlice.reducer;
