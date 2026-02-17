import { useState } from 'react';
import { useAddNode } from '../api';
import type { AddNodeForm as AddNodeFormData } from '../types';
import { EMPTY_ADD_NODE_FORM } from '../types';

interface AddNodeFormProps {
  onError: (msg: string) => void;
}

export default function AddNodeForm({ onError }: AddNodeFormProps) {
  const { trigger: addNode } = useAddNode();
  const [form, setForm] = useState<AddNodeFormData>(EMPTY_ADD_NODE_FORM);

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      await addNode({ method: 'POST', body: { name: form.name } });
      setForm(EMPTY_ADD_NODE_FORM);
    } catch (err) {
      onError(String(err));
    }
  };

  return (
    <>
      <h2>Add Node</h2>
      <form onSubmit={handleSubmit}>
        <table style={{ width: '100%' }}>
          <tbody>
            <tr>
              <td style={{ whiteSpace: 'nowrap', width: '1%', paddingRight: '1rem' }}>Name</td>
              <td><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. tokyo-1" required /></td>
            </tr>
          </tbody>
        </table>
        <button type="submit" style={{ marginTop: '0.5rem' }}>Add Node</button>
      </form>
    </>
  );
}
