import { useCallback, useState, useEffect } from 'react';
import { useClipboard } from 'foxact/use-clipboard';
import QRCode from 'qrcode';
import { formatBytes, formatExpiry } from '../utils/format';
import type { MeResponse } from '../types';

interface UserDashboardPageProps {
  data: MeResponse;
  password: string;
  onLogout: () => void;
  onRefresh: () => void;
  refreshing: boolean;
}

function QRDialog({ url, name, onClose }: { url: string; name: string; onClose: () => void }) {
  const [dataUrl, setDataUrl] = useState('');
  useEffect(() => {
    QRCode.toDataURL(url, { width: 256, margin: 2 }).then(setDataUrl);
  }, [url]);

  return (
    <dialog open style={{ position: 'fixed', top: '10vh', left: '50%', transform: 'translateX(-50%)', padding: '1rem', border: '1px solid #ccc', borderRadius: '4px', zIndex: 1000, textAlign: 'center' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
        <strong>{name}</strong>
        <button onClick={onClose}>Close</button>
      </div>
      {dataUrl ? <img src={dataUrl} alt="QR Code" style={{ width: 256, height: 256 }} /> : <p>Generating…</p>}
      <p style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.75em', maxWidth: 256, margin: '0.5rem auto 0' }}>{url}</p>
    </dialog>
  );
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
  const [qrTarget, setQrTarget] = useState<{ url: string; name: string } | null>(null);

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
              <th style={{ width: '14em' }}>action</th>
            </tr>
          </thead>
          <tbody>
            {sub_templates.map((name) => {
              const url = `${location.origin}/sub/${name}?pwd=${encodeURIComponent(password)}`;
              return (
                <tr key={name}>
                  <td>{name}</td>
                  <td style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{url}</td>
                  <td>
                    <CopyButton text={url} />{' '}
                    <button onClick={() => setQrTarget({ url, name })}>QR</button>{' '}
                    <a href={`${url}&preview=1`} target="_blank" rel="noreferrer">
                      <button>Preview</button>
                    </a>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {qrTarget && <QRDialog url={qrTarget.url} name={qrTarget.name} onClose={() => setQrTarget(null)} />}

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
