import { useState } from 'react';
import { useUpdateUser, useDeleteUser, USERS_KEY } from '../api';
import { formatBytes, formatExpiry } from '../utils/format';
import type { User, EditData } from '../types';

interface UserTableProps {
  users: User[];
  onError: (msg: string) => void;
}

function UserRow({ user, onError }: { user: User; onError: (msg: string) => void }) {
  const { trigger: updateUser } = useUpdateUser();
  const { trigger: deleteUser } = useDeleteUser();
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState<EditData>({
    username: '', traffic_limit: '0', traffic_used: '0', expires_at: '0', enabled: true,
  });

  const startEdit = () => {
    setEditing(true);
    setEditData({
      username: user.username,
      traffic_limit: String(user.traffic_limit),
      traffic_used: String(user.traffic_used),
      expires_at: String(user.expires_at),
      enabled: user.enabled,
    });
  };

  const saveEdit = async () => {
    try {
      await updateUser({
        method: 'PATCH',
        path: `${USERS_KEY}/${user.id}`,
        body: {
          username: editData.username || undefined,
          traffic_limit: editData.traffic_limit !== undefined ? Number(editData.traffic_limit) : undefined,
          traffic_used: editData.traffic_used !== undefined ? Number(editData.traffic_used) : undefined,
          expires_at: editData.expires_at !== undefined ? Number(editData.expires_at) : undefined,
          enabled: editData.enabled,
        },
      });
      setEditing(false);
    } catch (err) {
      onError(String(err));
    }
  };

  const handleDelete = async () => {
    if (!confirm(`Delete user ${user.username}?`)) return;
    try {
      await deleteUser({ method: 'DELETE', path: `${USERS_KEY}/${user.id}` });
    } catch (err) {
      onError(String(err));
    }
  };

  if (editing) {
    return (
      <tr>
        <td>{user.id}</td>
        <td><input value={editData.username} onChange={(e) => setEditData({ ...editData, username: e.target.value })} /></td>
        <td>{user.hash}</td>
        <td><input type="number" value={editData.traffic_used} onChange={(e) => setEditData({ ...editData, traffic_used: e.target.value })} style={{ width: '100px' }} /></td>
        <td><input type="number" value={editData.traffic_limit} onChange={(e) => setEditData({ ...editData, traffic_limit: e.target.value })} style={{ width: '100px' }} /></td>
        <td><input type="number" value={editData.expires_at} onChange={(e) => setEditData({ ...editData, expires_at: e.target.value })} style={{ width: '120px' }} /></td>
        <td><input type="checkbox" checked={editData.enabled} onChange={(e) => setEditData({ ...editData, enabled: e.target.checked })} /></td>
        <td>
          <button onClick={saveEdit}>Save</button>
          <button onClick={() => setEditing(false)}>Cancel</button>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td>{user.id}</td>
      <td>{user.username}</td>
      <td style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em' }}>{user.hash}</td>
      <td>{formatBytes(user.traffic_used)}</td>
      <td>{user.traffic_limit === 0 ? '∞' : formatBytes(user.traffic_limit)}</td>
      <td>{formatExpiry(user.expires_at)}</td>
      <td>{user.enabled ? '✓' : '✗'}</td>
      <td>
        <button onClick={startEdit}>Edit</button>
        <button onClick={handleDelete}>Delete</button>
      </td>
    </tr>
  );
}

export default function UserTable({ users, onError }: UserTableProps) {
  return (
    <>
      <h2>Users ({users.length})</h2>
      <table border={1} cellPadding={4} style={{ width: '100%', tableLayout: 'fixed' }}>
        <thead>
          <tr>
            <th>id</th>
            <th>username</th>
            <th>hash</th>
            <th>traffic_used</th>
            <th>traffic_limit</th>
            <th>expires_at</th>
            <th>enabled</th>
            <th>actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <UserRow key={u.id} user={u} onError={onError} />
          ))}
        </tbody>
      </table>
    </>
  );
}
