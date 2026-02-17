import { createRoot } from 'react-dom/client';
import { SWRConfig } from 'swr';
import { Route, Switch, Redirect } from 'wouter';
import { authMiddleware } from './api';
import { useToken } from './hooks/useToken';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';

function App() {
  const [token, setToken] = useToken();
  const isAuthed = !!token;

  return (
    <SWRConfig value={{ use: [authMiddleware] }}>
      <Switch>
        <Route path="/login">
          {isAuthed ? <Redirect to="/" /> : <LoginPage onLogin={(t) => setToken(t)} />}
        </Route>
        <Route path="/">
          {isAuthed ? <DashboardPage onLogout={() => setToken(null)} /> : <Redirect to="/login" />}
        </Route>
      </Switch>
    </SWRConfig>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
