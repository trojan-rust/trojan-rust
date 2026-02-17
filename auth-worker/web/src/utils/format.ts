import humanFormat from 'human-format';

const bytesScale = new humanFormat.Scale({
  B: 1,
  KB: 1024,
  MB: 1024 ** 2,
  GB: 1024 ** 3,
  TB: 1024 ** 4,
});

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  return humanFormat(bytes, { scale: bytesScale });
}

export function formatExpiry(ts: number): string {
  if (ts === 0) return 'never';
  return new Date(ts * 1000).toLocaleString();
}
