export interface User {
  id: number;
  hash: string;
  username: string;
  password?: string;
  traffic_limit: number;
  traffic_used: number;
  expires_at: number;
  enabled: boolean;
}

export interface EditData {
  username: string;
  traffic_limit: string;
  traffic_used: string;
  expires_at: string;
  enabled: boolean;
}

export interface AddForm {
  password: string;
  username: string;
  traffic_limit: string;
  expires_at: string;
  enabled: boolean;
}

export const EMPTY_ADD_FORM: AddForm = {
  password: '',
  username: '',
  traffic_limit: '0',
  expires_at: '0',
  enabled: true,
};

// ── Nodes ────────────────────────────────────────────────────────

export interface Node {
  id: number;
  name: string;
  token: string;
  enabled: boolean;
  ip: string;
  last_seen: number;
  created_at: number;
}

export interface AddNodeForm {
  name: string;
}

export const EMPTY_ADD_NODE_FORM: AddNodeForm = {
  name: '',
};

// ── Traffic Logs ─────────────────────────────────────────────────

export interface TrafficLog {
  id: number;
  user_id: number;
  node_id: number;
  bytes: number;
  recorded_at: number;
}
