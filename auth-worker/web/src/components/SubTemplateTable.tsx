import { useState } from 'react';
import { useUpdateSubTemplate, useDeleteSubTemplate, SUB_TEMPLATES_KEY } from '../api';
import type { SubTemplate, EditSubTemplateData } from '../types';

interface SubTemplateTableProps {
  templates: SubTemplate[];
  onError: (msg: string) => void;
}

function SubTemplateRow({ tpl, onError }: { tpl: SubTemplate; onError: (msg: string) => void }) {
  const { trigger: updateTemplate } = useUpdateSubTemplate();
  const { trigger: deleteTemplate } = useDeleteSubTemplate();
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState<EditSubTemplateData>({
    name: '', filename: '', content: '', content_type: '',
  });

  const startEdit = () => {
    setEditing(true);
    setEditData({
      name: tpl.name,
      filename: tpl.filename,
      content: tpl.content,
      content_type: tpl.content_type,
    });
  };

  const saveEdit = async () => {
    try {
      await updateTemplate({
        method: 'PATCH',
        path: `${SUB_TEMPLATES_KEY}/${tpl.id}`,
        body: {
          name: editData.name || undefined,
          filename: editData.filename,
          content: editData.content,
          content_type: editData.content_type || undefined,
        },
      });
      setEditing(false);
    } catch (err) {
      onError(String(err));
    }
  };

  const handleDelete = async () => {
    if (!confirm(`Delete template "${tpl.name}"?`)) return;
    try {
      await deleteTemplate({ method: 'DELETE', path: `${SUB_TEMPLATES_KEY}/${tpl.id}` });
    } catch (err) {
      onError(String(err));
    }
  };

  if (editing) {
    return (
      <tr>
        <td>{tpl.id}</td>
        <td><input value={editData.name} onChange={(e) => setEditData({ ...editData, name: e.target.value })} /></td>
        <td><input value={editData.filename} onChange={(e) => setEditData({ ...editData, filename: e.target.value })} placeholder="download filename" /></td>
        <td><textarea value={editData.content} onChange={(e) => setEditData({ ...editData, content: e.target.value })} rows={4} style={{ width: '100%', fontFamily: 'monospace', fontSize: '0.85em' }} /></td>
        <td><input value={editData.content_type} onChange={(e) => setEditData({ ...editData, content_type: e.target.value })} /></td>
        <td>
          <button onClick={saveEdit}>Save</button>
          <button onClick={() => setEditing(false)}>Cancel</button>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td>{tpl.id}</td>
      <td>{tpl.name}</td>
      <td>{tpl.filename || <span style={{ opacity: 0.4 }}>—</span>}</td>
      <td><pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em', margin: 0, maxHeight: '6em', overflow: 'auto' }}>{tpl.content}</pre></td>
      <td>{tpl.content_type}</td>
      <td>
        <button onClick={startEdit}>Edit</button>
        <button onClick={handleDelete}>Delete</button>
      </td>
    </tr>
  );
}

export default function SubTemplateTable({ templates, onError }: SubTemplateTableProps) {
  return (
    <>
      <h2>Sub Templates ({templates.length})</h2>
      <table border={1} cellPadding={4} style={{ width: '100%', tableLayout: 'fixed' }}>
        <thead>
          <tr>
            <th style={{ width: '4em' }}>id</th>
            <th style={{ width: '10em' }}>name</th>
            <th style={{ width: '10em' }}>filename</th>
            <th>content</th>
            <th style={{ width: '10em' }}>content_type</th>
            <th style={{ width: '10em' }}>actions</th>
          </tr>
        </thead>
        <tbody>
          {templates.map((t) => (
            <SubTemplateRow key={t.id} tpl={t} onError={onError} />
          ))}
        </tbody>
      </table>
    </>
  );
}
