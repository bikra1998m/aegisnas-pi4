import CrudPage from '../components/CrudPage';

export default function Vouchers() {
  return (
    <CrudPage
      title="Vouchers"
      endpoint="/vouchers"
      itemName="Voucher"
      columns={[
        { key: 'code', label: 'Code' },
        { key: 'role', label: 'Role' },
        { key: 'duration_minutes', label: 'Duration' },
        { key: 'usage_limit', label: 'Usage Limit' },
        { key: 'used_count', label: 'Used' },
        { key: 'expires_at', label: 'Expires At' },
      ]}
      fields={[
        { name: 'code', label: 'Code', required: true },
        { name: 'role', label: 'Role', required: true, defaultValue: 'guest-basic' },
        { name: 'duration_minutes', label: 'Duration Minutes', type: 'number', required: true, defaultValue: 1440 },
        { name: 'usage_limit', label: 'Usage Limit', type: 'number', required: true, defaultValue: 1 },
        { name: 'expires_at', label: 'Expires At', placeholder: '2026-12-31T23:59:59Z' },
      ]}
    />
  );
}
