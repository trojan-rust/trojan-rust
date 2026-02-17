import useSWR, { type Middleware } from 'swr';
import useSWRMutation from 'swr/mutation';
import type { Node, User } from './types';
import { useTokenValue } from './hooks/useToken';

export const USERS_KEY = '/admin/users';
export const NODES_KEY = '/admin/nodes';

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

export function useMigrate() {
  return useSWRMutation<string, Error, string, MutationArg>('/admin/migrate', mutationFetcher);
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
