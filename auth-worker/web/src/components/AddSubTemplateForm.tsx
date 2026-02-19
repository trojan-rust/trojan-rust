import { useState } from 'react';
import { useAddSubTemplate } from '../api';
import type { AddSubTemplateForm as FormType } from '../types';
import { EMPTY_ADD_SUB_TEMPLATE_FORM } from '../types';

interface AddSubTemplateFormProps {
  onError: (msg: string) => void;
}

export default function AddSubTemplateForm({ onError }: AddSubTemplateFormProps) {
  const { trigger: addTemplate } = useAddSubTemplate();
  const [form, setForm] = useState<FormType>(EMPTY_ADD_SUB_TEMPLATE_FORM);

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      await addTemplate({
        method: 'POST',
        body: {
          name: form.name,
          filename: form.filename || undefined,
          content: form.content,
          content_type: form.content_type,
        },
      });
      setForm(EMPTY_ADD_SUB_TEMPLATE_FORM);
    } catch (err) {
      onError(String(err));
    }
  };

  return (
    <>
      <h2>Add Sub Template</h2>
      <form onSubmit={handleSubmit}>
        <table style={{ width: '100%' }}>
          <tbody>
            <tr><td style={{ whiteSpace: 'nowrap', width: '1%', paddingRight: '1rem' }}>Name</td><td><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required placeholder="e.g. clash-config" /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Filename</td><td><input value={form.filename} onChange={(e) => setForm({ ...form, filename: e.target.value })} placeholder="e.g. config.yaml (download filename)" /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap' }}>Content Type</td><td><input value={form.content_type} onChange={(e) => setForm({ ...form, content_type: e.target.value })} placeholder="text/plain" /></td></tr>
            <tr><td style={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>Content</td><td><textarea value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} rows={8} style={{ width: '100%', fontFamily: 'monospace', fontSize: '0.85em' }} placeholder="Use {{ pwd }} as password placeholder" /></td></tr>
          </tbody>
        </table>
        <button type="submit" style={{ marginTop: '0.5rem' }}>Add Template</button>
      </form>
    </>
  );
}
