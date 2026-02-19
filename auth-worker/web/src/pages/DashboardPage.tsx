import { useState } from 'react';
import { useUsers, useNodes, useSubTemplates, useMigrate, useVersion } from '../api';
import UserTable from '../components/UserTable';
import AddUserForm from '../components/AddUserForm';
import NodeTable from '../components/NodeTable';
import AddNodeForm from '../components/AddNodeForm';
import SubTemplateTable from '../components/SubTemplateTable';
import AddSubTemplateForm from '../components/AddSubTemplateForm';

interface DashboardPageProps {
  onLogout: () => void;
}

export default function DashboardPage({ onLogout }: DashboardPageProps) {
  const { data: users = [], isLoading: usersLoading, mutate: mutateUsers } = useUsers();
  const { data: nodes = [], isLoading: nodesLoading, mutate: mutateNodes } = useNodes();
  const { data: subTemplates = [], isLoading: subTemplatesLoading, mutate: mutateSubTemplates } = useSubTemplates();
  const { trigger: migrate, isMutating: migrating } = useMigrate();
  const { data: version } = useVersion();
  const [error, setError] = useState('');

  const isLoading = usersLoading || nodesLoading || subTemplatesLoading;

  const handleRefresh = () => {
    mutateUsers();
    mutateNodes();
    mutateSubTemplates();
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
                mutateSubTemplates();
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

      <hr style={{ margin: '2rem 0' }} />

      <SubTemplateTable templates={subTemplates} onError={setError} />
      <AddSubTemplateForm onError={setError} />
    </div>
  );
}
