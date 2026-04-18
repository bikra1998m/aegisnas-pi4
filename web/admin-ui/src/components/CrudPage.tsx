import { useEffect, useMemo, useState } from 'react';
import type React from 'react';
import api from '../api/client';

export interface Column<T = any> {
  key: string;
  label: string;
  render?: (item: T) => React.ReactNode;
}

export interface Field {
  name: string;
  label: string;
  type?: 'text' | 'number' | 'password' | 'textarea' | 'checkbox' | 'json';
  required?: boolean;
  createOnly?: boolean;
  placeholder?: string;
  defaultValue?: string | number | boolean;
}

interface CrudPageProps {
  title: string;
  endpoint: string;
  columns: Column[];
  fields: Field[];
  itemName: string;
}

const emptyValue = (field: Field) => {
  if (field.defaultValue !== undefined) return field.defaultValue;
  if (field.type === 'checkbox') return false;
  return '';
};

const valueForEdit = (item: any, field: Field) => {
  if (field.type === 'password') return '';
  const value = item[field.name];
  if (value === null || value === undefined) return emptyValue(field);
  if (field.type === 'json') return JSON.stringify(value, null, 2);
  return value;
};

export default function CrudPage({ title, endpoint, columns, fields, itemName }: CrudPageProps) {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<any | null>(null);
  const initialForm = useMemo(
    () => Object.fromEntries(fields.map((field) => [field.name, emptyValue(field)])),
    [fields]
  );
  const [form, setForm] = useState<Record<string, any>>(initialForm);

  const fetchItems = async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(endpoint);
      setItems(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
    const handler = () => fetchItems();
    window.addEventListener('config-applied', handler);
    return () => window.removeEventListener('config-applied', handler);
  }, [endpoint]);

  useEffect(() => {
    setForm(initialForm);
  }, [initialForm]);

  const openCreate = () => {
    setEditing(null);
    setForm(initialForm);
    setShowModal(true);
  };

  const openEdit = (item: any) => {
    setEditing(item);
    setForm(Object.fromEntries(fields.map((field) => [field.name, valueForEdit(item, field)])));
    setShowModal(true);
  };

  const buildPayload = () => {
    const payload: Record<string, any> = {};
    for (const field of fields) {
      if (field.createOnly && editing) continue;
      const value = form[field.name];
      if (field.type === 'password' && editing && !value) continue;
      if (field.type === 'number') {
        payload[field.name] = value === '' || value === null || value === undefined ? null : Number(value);
      } else if (field.type === 'checkbox') {
        payload[field.name] = Boolean(value);
      } else if (field.type === 'json') {
        payload[field.name] = value ? JSON.parse(value) : {};
      } else {
        payload[field.name] = value ?? '';
      }
    }
    return payload;
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    try {
      const payload = buildPayload();
      if (editing) {
        await api.put(`${endpoint}/${editing.id}`, payload);
      } else {
        await api.post(endpoint, payload);
      }
      setMessage('Change staged. Review and apply it from the pending changes bar.');
      setShowModal(false);
      window.dispatchEvent(new Event('staged-changes-updated'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not stage change.');
    }
  };

  const remove = async (item: any) => {
    if (!confirm(`Delete ${itemName} "${item.name || item.username || item.code || item.id}"?`)) return;
    setError('');
    try {
      await api.delete(`${endpoint}/${item.id}`);
      setMessage('Delete staged. Review and apply it from the pending changes bar.');
      window.dispatchEvent(new Event('staged-changes-updated'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not stage delete.');
    }
  };

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-2xl font-bold text-gray-900">{title}</h2>
        <button onClick={openCreate} className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800">
          Add {itemName}
        </button>
      </div>

      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <div className="overflow-x-auto rounded-lg bg-white shadow">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              {columns.map((column) => (
                <th key={column.key} className="px-5 py-3 text-left text-xs font-semibold uppercase text-gray-600">
                  {column.label}
                </th>
              ))}
              <th className="px-5 py-3 text-right text-xs font-semibold uppercase text-gray-600">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 bg-white">
            {loading ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={columns.length + 1}>Loading...</td></tr>
            ) : items.length === 0 ? (
              <tr><td className="px-5 py-6 text-gray-500" colSpan={columns.length + 1}>No records yet.</td></tr>
            ) : (
              items.map((item) => (
                <tr key={item.id}>
                  {columns.map((column) => (
                    <td key={column.key} className="max-w-xs px-5 py-4 text-sm text-gray-800">
                      {column.render ? column.render(item) : String(item[column.key] ?? '')}
                    </td>
                  ))}
                  <td className="px-5 py-4 text-right text-sm">
                    <button onClick={() => openEdit(item)} className="mr-3 text-sky-700 hover:text-sky-900">Edit</button>
                    <button onClick={() => remove(item)} className="text-red-700 hover:text-red-900">Delete</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black bg-opacity-50 p-4">
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-lg bg-white p-6 shadow-xl">
            <h3 className="mb-4 text-lg font-bold">{editing ? `Edit ${itemName}` : `Add ${itemName}`}</h3>
            <form onSubmit={submit} className="space-y-4">
              {fields.map((field) => (
                <label key={field.name} className="block text-sm font-medium text-gray-700">
                  <span>{field.label}</span>
                  {field.type === 'textarea' || field.type === 'json' ? (
                    <textarea
                      value={form[field.name] as string}
                      onChange={(event) => setForm({ ...form, [field.name]: event.target.value })}
                      className="mt-1 min-h-28 w-full rounded-md border px-3 py-2 font-mono text-sm"
                      placeholder={field.placeholder}
                      required={field.required}
                    />
                  ) : field.type === 'checkbox' ? (
                    <input
                      type="checkbox"
                      checked={Boolean(form[field.name])}
                      onChange={(event) => setForm({ ...form, [field.name]: event.target.checked })}
                      className="ml-3 h-4 w-4"
                    />
                  ) : (
                    <input
                      type={field.type || 'text'}
                      value={form[field.name] as string | number}
                      onChange={(event) => setForm({ ...form, [field.name]: event.target.value })}
                      className="mt-1 w-full rounded-md border px-3 py-2"
                      placeholder={field.placeholder}
                      required={field.required && !(field.type === 'password' && editing)}
                      disabled={field.createOnly && Boolean(editing)}
                    />
                  )}
                </label>
              ))}
              <div className="flex justify-end gap-3 pt-2">
                <button type="button" onClick={() => setShowModal(false)} className="rounded-md border px-4 py-2">
                  Cancel
                </button>
                <button type="submit" className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800">
                  Stage {editing ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
