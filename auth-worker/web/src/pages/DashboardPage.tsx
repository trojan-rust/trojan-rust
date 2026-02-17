import { useState } from 'react';
import { useUsers, useNodes, useMigrate, useVersion } from '../api';
import UserTable from '../components/UserTable';
import AddUserForm from '../components/AddUserForm';
import NodeTable from '../components/NodeTable';
import AddNodeForm from '../components/AddNodeForm';

interface DashboardPageProps {
  onLogout: () => void;
}

export default function DashboardPage({ onLogout }: DashboardPageProps) {
  const { data: users = [], isLoading: usersLoading, mutate: mutateUsers } = useUsers();
  const { data: nodes = [], isLoading: nodesLoading, mutate: mutateNodes } = useNodes();
  const { trigger: migrate, isMutating: migrating } = useMigrate();
  const { data: version } = useVersion();
  const [error, setError] = useState('');

  const isLoading = usersLoading || nodesLoading;

  const handleRefresh = () => {
    mutateUsers();
    mutateNodes();
  };

  return (
    <div>
      <h1>
        Auth Panel{version && <span style={{ fontSize: '0.5em', fontWeight: 'normal', marginLeft: '0.5rem', opacity: 0.5 }}>v{version}</span>}
        <span style={{ float: 'right' }}>
          <button onClick={handleRefresh} disabled={isLoading}>
            {isLoading ? 'Loading…' : 'Refresh'}
          </button>
          {' '}
          <button
            onClick={async () => {
              try {
                await migrate({ method: 'POST' });
                mutateUsers();
                mutateNodes();
              } catch (err) {
                setError(String(err));
              }
            }}
            disabled={migrating}
          >
            {migrating ? 'Migrating…' : 'Migrate'}
          </button>
          {' '}
          <button onClick={onLogout}>Logout</button>
        </span>
      </h1>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      <UserTable users={users} onError={setError} />
      <AddUserForm onError={setError} />

      <hr style={{ margin: '2rem 0' }} />

      <NodeTable nodes={nodes} onError={setError} />
      <AddNodeForm onError={setError} />
    </div>
  );
}
