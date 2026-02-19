import useSWR, { type Middleware } from 'swr';
import useSWRMutation from 'swr/mutation';
import type { MeResponse, Node, SubTemplate, TrafficLog, User } from './types';
import { useTokenValue } from './hooks/useToken';

export const USERS_KEY = '/admin/users';
export const NODES_KEY = '/admin/nodes';
export const TRAFFIC_KEY = '/admin/traffic';
export const SUB_TEMPLATES_KEY = '/admin/sub-templates';

// SWR Auth middleware
// Skips fetch when no token is present (returns null key).
export const authMiddleware: Middleware = (useSWRNext) => (key, fetcher, config) => {
  const token = useTokenValue();
  return useSWRNext(token ? key : null, fetcher, config);
};

function getToken(): string {
  try {
    const raw = localStorage.getItem('admin-token');
    return raw ? JSON.parse(raw) : '';
  } catch {
    return '';
  }
}

async function request<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const opts: RequestInit = {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  const ct = res.headers.get('content-type') ?? '';
  return (ct.includes('json') ? res.json() : res.text()) as T;
}

// ── SWR mutation fetchers ────────────────────────────────────────

interface MutationArg<T = unknown> {
  method: string;
  path?: string;
  body?: T;
}

function mutationFetcher<T>(key: string, { arg }: { arg: MutationArg }): Promise<T> {
  return request<T>(arg.method, arg.path ?? key, arg.body);
}

// ── Query hooks ──────────────────────────────────────────────────

const getFetcher = <T,>(url: string) => request<T>('GET', url);

export function useUsers() {
  return useSWR(USERS_KEY, getFetcher<User[]>);
}

export function useNodes() {
  return useSWR(NODES_KEY, getFetcher<Node[]>);
}

export function useSubTemplates() {
  return useSWR(SUB_TEMPLATES_KEY, getFetcher<SubTemplate[]>);
}

export function useTrafficLogs(userId: number | null) {
  const key = userId != null ? `${TRAFFIC_KEY}?user_id=${userId}` : null;
  return useSWR(key, getFetcher<TrafficLog[]>);
}

export function useVersion() {
  return useSWR('/admin/version', getFetcher<string>);
}

// ── Mutation hooks ───────────────────────────────────────────────

export function useAddUser() {
  return useSWRMutation<User, Error, string, MutationArg>(USERS_KEY, mutationFetcher);
}

export function useUpdateUser() {
  return useSWRMutation<User, Error, string, MutationArg>(USERS_KEY, mutationFetcher);
}

export function useDeleteUser() {
  return useSWRMutation<unknown, Error, string, MutationArg>(USERS_KEY, mutationFetcher);
}

export function useAddNode() {
  return useSWRMutation<Node, Error, string, MutationArg>(NODES_KEY, mutationFetcher);
}

export function useUpdateNode() {
  return useSWRMutation<Node, Error, string, MutationArg>(NODES_KEY, mutationFetcher);
}

export function useDeleteNode() {
  return useSWRMutation<unknown, Error, string, MutationArg>(NODES_KEY, mutationFetcher);
}

export function useRotateNodeToken() {
  return useSWRMutation<Node, Error, string, MutationArg>(NODES_KEY, mutationFetcher);
}

export function useAddSubTemplate() {
  return useSWRMutation<SubTemplate, Error, string, MutationArg>(SUB_TEMPLATES_KEY, mutationFetcher);
}

export function useUpdateSubTemplate() {
  return useSWRMutation<SubTemplate, Error, string, MutationArg>(SUB_TEMPLATES_KEY, mutationFetcher);
}

export function useDeleteSubTemplate() {
  return useSWRMutation<unknown, Error, string, MutationArg>(SUB_TEMPLATES_KEY, mutationFetcher);
}

export function useMigrate() {
  return useSWRMutation<string, Error, string, MutationArg>('/admin/migrate', mutationFetcher);
}

// ── User self-service (Basic Auth) ───────────────────────────────

export async function fetchMe(username: string, password: string): Promise<MeResponse> {
  const basic = btoa(`${username}:${password}`);
  const res = await fetch('/me', {
    headers: { Authorization: `Basic ${basic}` },
  });
  if (!res.ok) {
    throw new Error(res.status === 401 ? 'Invalid username or password' : `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Standalone (non-hook) ────────────────────────────────────────

export async function verifyToken(token: string): Promise<boolean> {
  try {
    const opts: RequestInit = {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    };
    const res = await fetch(USERS_KEY, opts);
    return res.ok;
  } catch {
    return false;
  }
}
