import { useState } from 'react';
import { fetchMe } from '../api';
import type { MeResponse } from '../types';

interface UserLoginPageProps {
  onLogin: (data: MeResponse, password: string) => void;
}

export default function UserLoginPage({ onLogin }: UserLoginPageProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;
    setLoading(true);
    setError('');
    try {
      const data = await fetchMe(username.trim(), password.trim());
      onLogin(data, password.trim());
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>User Portal</h1>
      <form onSubmit={handleSubmit}>
        <fieldset>
          <legend>Login</legend>
          <div style={{ marginBottom: '0.5rem' }}>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              style={{ width: '300px' }}
              required
            />
          </div>
          <div style={{ marginBottom: '0.5rem' }}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              style={{ width: '300px' }}
              required
            />
          </div>
          <button type="submit" disabled={loading}>
            {loading ? 'Logging in…' : 'Login'}
          </button>
          {error && <p style={{ color: 'red' }}>{error}</p>}
        </fieldset>
      </form>
    </div>
  );
}
