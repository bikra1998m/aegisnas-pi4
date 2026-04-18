import CrudPage from '../components/CrudPage';

export default function PortalProfiles() {
  return (
    <CrudPage
      title="Portal Profiles"
      endpoint="/portal-profiles"
      itemName="Portal Profile"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'branding', label: 'Branding' },
        { key: 'success_url', label: 'Success URL' },
        { key: 'logout_url', label: 'Logout URL' },
        { key: 'terms_text', label: 'Terms' },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'branding', label: 'Branding', required: true },
        { name: 'success_url', label: 'Success URL' },
        { name: 'logout_url', label: 'Logout URL' },
        { name: 'terms_text', label: 'Terms Text', type: 'textarea' },
      ]}
    />
  );
}
