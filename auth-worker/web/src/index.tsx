import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { SWRConfig } from 'swr';
import { Route, Switch, Redirect } from 'wouter';
import { authMiddleware, fetchMe } from './api';
import { useToken } from './hooks/useToken';
import type { MeResponse } from './types';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import UserLoginPage from './pages/UserLoginPage';
import UserDashboardPage from './pages/UserDashboardPage';

function App() {
  const [token, setToken] = useToken();
  const isAuthed = !!token;

  // User portal state (session-only, not persisted)
  const [userData, setUserData] = useState<MeResponse | null>(null);
  const [userPassword, setUserPassword] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const handleUserLogin = (data: MeResponse, password: string) => {
    setUserData(data);
    setUserPassword(password);
  };

  const handleUserLogout = () => {
    setUserData(null);
    setUserPassword('');
  };

  const handleUserRefresh = async () => {
    if (!userData || !userPassword) return;
    setRefreshing(true);
    try {
      const data = await fetchMe(userData.user.username, userPassword);
      setUserData(data);
    } catch {
      handleUserLogout();
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <SWRConfig value={{ use: [authMiddleware] }}>
      <Switch>
        {/* Admin routes (more specific, must come first) */}
        <Route path="/admin/login">
          {isAuthed ? <Redirect to="/admin" /> : <LoginPage onLogin={(t) => setToken(t)} />}
        </Route>
        <Route path="/admin">
          {isAuthed ? <DashboardPage onLogout={() => setToken(null)} /> : <Redirect to="/admin/login" />}
        </Route>

        {/* User routes (default) */}
        <Route path="/login">
          {userData ? <Redirect to="/" /> : <UserLoginPage onLogin={handleUserLogin} />}
        </Route>
        <Route path="/">
          {userData ? (
            <UserDashboardPage
              data={userData}
              password={userPassword}
              onLogout={handleUserLogout}
              onRefresh={handleUserRefresh}
              refreshing={refreshing}
            />
          ) : (
            <Redirect to="/login" />
          )}
        </Route>
      </Switch>
    </SWRConfig>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
