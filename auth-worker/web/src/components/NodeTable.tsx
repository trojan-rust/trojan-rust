import { useState, useCallback } from 'react';
import { useClipboard } from 'foxact/use-clipboard';
import { useUpdateNode, useDeleteNode, useRotateNodeToken, NODES_KEY } from '../api';
import type { Node } from '../types';

interface NodeTableProps {
  nodes: Node[];
  onError: (msg: string) => void;
}

function formatTime(ts: number): string {
  if (ts === 0) return 'never';
  return new Date(ts * 1000).toLocaleString();
}

function NodeRow({ node, onError }: { node: Node; onError: (msg: string) => void }) {
  const { trigger: updateNode } = useUpdateNode();
  const { trigger: deleteNode } = useDeleteNode();
  const { trigger: rotateNodeToken } = useRotateNodeToken();
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const { copy, copied } = useClipboard({ timeout: 2000 });

  const handleCopyToken = useCallback(() => {
    copy(node.token);
  }, [copy, node.token]);

  const startEdit = () => {
    setEditing(true);
    setEditName(node.name);
  };

  const saveEdit = async () => {
    try {
      await updateNode({ method: 'PATCH', path: `${NODES_KEY}/${node.id}`, body: { name: editName } });
      setEditing(false);
    } catch (err) {
      onError(String(err));
    }
  };

  const toggleEnabled = async () => {
    try {
      await updateNode({ method: 'PATCH', path: `${NODES_KEY}/${node.id}`, body: { enabled: !node.enabled } });
    } catch (err) {
      onError(String(err));
    }
  };

  const rotateToken = async () => {
    if (!confirm(`Rotate token for node "${node.name}"? The old token will stop working immediately.`)) return;
    try {
      await rotateNodeToken({ method: 'POST', path: `${NODES_KEY}/${node.id}/rotate` });
    } catch (err) {
      onError(String(err));
    }
  };

  const handleDelete = async () => {
    if (!confirm(`Delete node "${node.name}"?`)) return;
    try {
      await deleteNode({ method: 'DELETE', path: `${NODES_KEY}/${node.id}` });
    } catch (err) {
      onError(String(err));
    }
  };

  if (editing) {
    return (
      <tr>
        <td>{node.id}</td>
        <td><input value={editName} onChange={(e) => setEditName(e.target.value)} /></td>
        <td style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{node.token}</td>
        <td>{node.enabled ? '✓' : '✗'}</td>
        <td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{node.ip || '-'}</td>
        <td>{formatTime(node.last_seen)}</td>
        <td>{formatTime(node.created_at)}</td>
        <td>
          <button onClick={saveEdit}>Save</button>
          <button onClick={() => setEditing(false)}>Cancel</button>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td>{node.id}</td>
      <td>{node.name}</td>
      <td
        onClick={handleCopyToken}
        style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em', cursor: 'pointer' }}
        title="Click to copy"
      >
        {copied ? 'Copied!' : node.token}
      </td>
      <td>{node.enabled ? '✓' : '✗'}</td>
      <td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{node.ip || '-'}</td>
      <td>{formatTime(node.last_seen)}</td>
      <td>{formatTime(node.created_at)}</td>
      <td>
        <button onClick={startEdit}>Edit</button>
        <button onClick={toggleEnabled}>{node.enabled ? 'Disable' : 'Enable'}</button>
        <button onClick={rotateToken}>Rotate</button>
        <button onClick={handleDelete}>Delete</button>
      </td>
    </tr>
  );
}

export default function NodeTable({ nodes, onError }: NodeTableProps) {
  return (
    <>
      <h2>Nodes ({nodes.length})</h2>
      <table border={1} cellPadding={4} style={{ width: '100%', tableLayout: 'fixed' }}>
        <thead>
          <tr>
            <th>id</th>
            <th>name</th>
            <th>token</th>
            <th>enabled</th>
            <th>ip</th>
            <th>last_seen</th>
            <th>created_at</th>
            <th>actions</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <NodeRow key={n.id} node={n} onError={onError} />
          ))}
        </tbody>
      </table>
    </>
  );
}
