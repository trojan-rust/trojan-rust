import { createLocalStorageState } from 'foxact/create-local-storage-state';

const [useToken, useTokenValue] = createLocalStorageState<string>(
  'admin-token',
  '',
);

export { useToken, useTokenValue };
