import { useState, useCallback } from 'react';
import { useClipboard } from 'foxact/use-clipboard';
import { useAddUser } from '../api';
import type { AddForm } from '../types';
import { EMPTY_ADD_FORM } from '../types';

interface AddUserFormProps {
  onError: (msg: string) => void;
}

export default function AddUserForm({ onError }: AddUserFormProps) {
  const { trigger: addUser } = useAddUser();
  const [form, setForm] = useState<AddForm>(EMPTY_ADD_FORM);
  const [createdPassword, setCreatedPassword] = useState('');
  const { copy, copied } = useClipboard({ timeout: 2000 });

  const handleCopy = useCallback(() => {
    if (createdPassword) copy(createdPassword);
  }, [copy, createdPassword]);

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const res = await addUser({
        method: 'POST',
        body: {
          password: form.password || undefined,
          username: form.username,
          traffic_limit: Number(form.traffic_limit),
          expires_at: Number(form.expires_at),
          enabled: form.enabled,
        },
      });
      setCreatedPassword(res?.password ?? '');
      setForm(EMPTY_ADD_FORM);
    } catch (err) {
      onError(String(err));
    }
  };

  return (
    <>
      <h2>Add User</h2>
      {createdPassword && (
        <p>
          Generated password:{' '}
          <code
            onClick={handleCopy}
            style={{ cursor: 'pointer', padding: '2px 6px', background: '#f0f0f0', borderRadius: 3 }}
          >
            {createdPassword}
          </code>{' '}
          <button type="button" onClick={handleCopy}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <table style={{ width: '100%' }}>
          <tbody>
            <tr><td style={{ whiteSpace: 'nowrap', width: '1%', paddingRight: '1rem' }}>Password</td><td><input value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Leave empty to auto-generate" /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Username</td><td><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Traffic Limit</td><td><input type="number" value={form.traffic_limit} onChange={(e) => setForm({ ...form, traffic_limit: e.target.value })} /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Expires At (unix)</td><td><input type="number" value={form.expires_at} onChange={(e) => setForm({ ...form, expires_at: e.target.value })} /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Enabled</td><td><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /></td></tr>
          </tbody>
        </table>
        <button type="submit" style={{ marginTop: '0.5rem' }}>Add User</button>
      </form>
    </>
  );
}
