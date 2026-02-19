import { useState } from 'react';
import { useUpdateSubTemplate, useDeleteSubTemplate, SUB_TEMPLATES_KEY } from '../api';
import type { SubTemplate, EditSubTemplateData } from '../types';

interface SubTemplateTableProps {
  templates: SubTemplate[];
  onError: (msg: string) => void;
}

function ContentDialog({ content, onClose, onSave }: { content: string; onClose: () => void; onSave?: (v: string) => void }) {
  const [value, setValue] = useState(content);
  const editable = !!onSave;

  return (
    <dialog open style={{ position: 'fixed', top: '10vh', left: '10vw', width: '80vw', maxWidth: '800px', maxHeight: '80vh', padding: '1rem', border: '1px solid #ccc', borderRadius: '4px', zIndex: 1000 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
        <strong>Content</strong>
        <span>
          {editable && <button onClick={() => { onSave(value); onClose(); }} style={{ marginRight: '0.5rem' }}>Save</button>}
          <button onClick={onClose}>Close</button>
        </span>
      </div>
      {editable
        ? <textarea value={value} onChange={(e) => setValue(e.target.value)} rows={20} style={{ width: '100%', fontFamily: 'monospace', fontSize: '0.85em', boxSizing: 'border-box' }} />
        : <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.85em', margin: 0, overflow: 'auto', maxHeight: 'calc(80vh - 4rem)' }}>{content}</pre>
      }
    </dialog>
  );
}

function SubTemplateRow({ tpl, onError }: { tpl: SubTemplate; onError: (msg: string) => void }) {
  const { trigger: updateTemplate } = useUpdateSubTemplate();
  const { trigger: deleteTemplate } = useDeleteSubTemplate();
  const [editing, setEditing] = useState(false);
  const [showContent, setShowContent] = useState(false);
  const [editData, setEditData] = useState<EditSubTemplateData>({
    name: '', filename: '', content: '', content_type: '', update_interval: '', profile_url: '',
  });

  const startEdit = () => {
    setEditing(true);
    setEditData({
      name: tpl.name,
      filename: tpl.filename,
      content: tpl.content,
      content_type: tpl.content_type,
      update_interval: tpl.update_interval,
      profile_url: tpl.profile_url,
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
          update_interval: editData.update_interval || undefined,
          profile_url: editData.profile_url,
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
        <td><input value={editData.content_type} onChange={(e) => setEditData({ ...editData, content_type: e.target.value })} /></td>
        <td><input value={editData.update_interval} onChange={(e) => setEditData({ ...editData, update_interval: e.target.value })} placeholder="e.g. 24h" /></td>
        <td><input value={editData.profile_url} onChange={(e) => setEditData({ ...editData, profile_url: e.target.value })} placeholder="https://..." /></td>
        <td>
          <button onClick={() => setShowContent(true)}>Content</button>
          {showContent && <ContentDialog content={editData.content} onClose={() => setShowContent(false)} onSave={(v) => setEditData({ ...editData, content: v })} />}
        </td>
        <td>
          <button onClick={saveEdit}>Save</button>{' '}
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
      <td>{tpl.content_type}</td>
      <td>{tpl.update_interval || <span style={{ opacity: 0.4 }}>—</span>}</td>
      <td style={{ wordBreak: 'break-all', fontSize: '0.85em' }}>{tpl.profile_url || <span style={{ opacity: 0.4 }}>—</span>}</td>
      <td>
        <button onClick={() => setShowContent(true)}>Content</button>
        {showContent && <ContentDialog content={tpl.content} onClose={() => setShowContent(false)} />}
      </td>
      <td>
        <button onClick={startEdit}>Edit</button>{' '}
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
            <th style={{ width: '3em' }}>id</th>
            <th style={{ width: '8em' }}>name</th>
            <th style={{ width: '8em' }}>filename</th>
            <th style={{ width: '10em' }}>content_type</th>
            <th style={{ width: '5em' }}>interval</th>
            <th>profile_url</th>
            <th style={{ width: '5em' }}>content</th>
            <th style={{ width: '8em' }}>actions</th>
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
