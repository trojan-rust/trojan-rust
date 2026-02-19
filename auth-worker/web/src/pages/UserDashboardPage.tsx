import { useCallback } from 'react';
import { useClipboard } from 'foxact/use-clipboard';
import { formatBytes, formatExpiry } from '../utils/format';
import type { MeResponse } from '../types';

interface UserDashboardPageProps {
  data: MeResponse;
  password: string;
  onLogout: () => void;
  onRefresh: () => void;
  refreshing: boolean;
}

function CopyButton({ text }: { text: string }) {
  const { copy, copied } = useClipboard({ timeout: 2000 });
  const handleCopy = useCallback(() => copy(text), [copy, text]);
  return (
    <button onClick={handleCopy} style={{ minWidth: '4em' }}>
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

export default function UserDashboardPage({ data, password, onLogout, onRefresh, refreshing }: UserDashboardPageProps) {
  const { user, traffic_by_node, sub_templates } = data;

  return (
    <div>
      <h1>
        {user.username}
        <span style={{ float: 'right' }}>
          <button onClick={onRefresh} disabled={refreshing}>
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>{' '}
          <button onClick={onLogout}>Logout</button>
        </span>
      </h1>

      <h2>Account</h2>
      <table border={1} cellPadding={4}>
        <tbody>
          <tr>
            <th>Traffic Used</th>
            <td>{formatBytes(user.traffic_used)}</td>
          </tr>
          <tr>
            <th>Traffic Limit</th>
            <td>{user.traffic_limit === 0 ? '∞' : formatBytes(user.traffic_limit)}</td>
          </tr>
          <tr>
            <th>Expires</th>
            <td>{formatExpiry(user.expires_at)}</td>
          </tr>
          <tr>
            <th>Status</th>
            <td>{user.enabled ? 'Active' : 'Disabled'}</td>
          </tr>
        </tbody>
      </table>

      <h2>Subscriptions ({sub_templates.length})</h2>
      {sub_templates.length === 0 ? (
        <p>No subscription templates available.</p>
      ) : (
        <table border={1} cellPadding={4} style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>name</th>
              <th>url</th>
              <th style={{ width: '5em' }}>action</th>
            </tr>
          </thead>
          <tbody>
            {sub_templates.map((name) => {
              const url = `${location.origin}/sub/${name}?pwd=${encodeURIComponent(password)}`;
              return (
                <tr key={name}>
                  <td>{name}</td>
                  <td style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{url}</td>
                  <td><CopyButton text={url} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <h2>Traffic by Node ({traffic_by_node.length})</h2>
      {traffic_by_node.length === 0 ? (
        <p>No traffic data yet.</p>
      ) : (
        <table border={1} cellPadding={4} style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>node</th>
              <th>traffic</th>
            </tr>
          </thead>
          <tbody>
            {traffic_by_node.map((row) => (
              <tr key={row.node_id}>
                <td>{row.node_name}</td>
                <td>{formatBytes(row.total_bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
