import { useState } from 'react';
import { useLocation } from 'wouter';
import { verifyToken } from '../api';

interface LoginPageProps {
  onLogin: (token: string) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [, navigate] = useLocation();

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!input.trim()) return;
    setLoading(true);
    setError('');
    const ok = await verifyToken(input.trim());
    setLoading(false);
    if (ok) {
      onLogin(input.trim());
      navigate('/');
    } else {
      setError('Invalid token');
    }
  };

  return (
    <div>
      <h1>Auth Panel</h1>
      <form onSubmit={handleSubmit}>
        <fieldset>
          <legend>Login</legend>
          <input
            type="password"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Admin token"
            style={{ width: '300px' }}
            required
          />
          {' '}
          <button type="submit" disabled={loading}>
            {loading ? 'Verifying…' : 'Login'}
          </button>
          {error && <p style={{ color: 'red' }}>{error}</p>}
        </fieldset>
      </form>
    </div>
  );
}
