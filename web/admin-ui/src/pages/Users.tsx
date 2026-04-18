import CrudPage from '../components/CrudPage';

export default function Users() {
  return (
    <CrudPage
      title="Users"
      endpoint="/users"
      itemName="User"
      columns={[
        { key: 'username', label: 'Username' },
        { key: 'role', label: 'Role' },
        { key: 'full_name', label: 'Full Name' },
        { key: 'email', label: 'Email' },
      ]}
      fields={[
        { name: 'username', label: 'Username', required: true, createOnly: true },
        { name: 'password', label: 'Password', type: 'password', required: true, placeholder: 'Leave blank on edit to keep current password' },
        { name: 'role', label: 'Role', required: true, defaultValue: 'guest-basic' },
        { name: 'full_name', label: 'Full Name' },
        { name: 'email', label: 'Email' },
      ]}
    />
  );
}
