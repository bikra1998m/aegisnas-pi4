import CrudPage from '../components/CrudPage';

export default function RadiusClients() {
  return (
    <CrudPage
      title="RADIUS Clients"
      endpoint="/radius-clients"
      itemName="RADIUS client"
      columns={[
        { key: 'shortname', label: 'Short Name' },
        { key: 'ip', label: 'IP Address' },
        { key: 'transport', label: 'Transport' },
        { key: 'nas_type', label: 'NAS Type / Vendor' },
        {
          key: 'secret_ref_set',
          label: 'Secret Ref',
          render: (item) => (item.secret_ref_set ? 'Yes' : 'No'),
        },
        { key: 'description', label: 'Description' },
        {
          key: 'enabled',
          label: 'Enabled',
          render: (item) => (item.enabled ? 'Yes' : 'No'),
        },
      ]}
      fields={[
        { name: 'shortname', label: 'Short Name', required: true },
        { name: 'ip', label: 'IP Address', required: true, placeholder: '10.20.0.2' },
        {
          name: 'transport',
          label: 'Transport',
          type: 'select',
          required: true,
          defaultValue: 'udp',
          options: [
            { value: 'udp', label: 'RADIUS / UDP' },
            { value: 'radsec', label: 'RadSec / TLS' },
          ],
        },
        { name: 'secret', label: 'Shared Secret (UDP only)', type: 'password' },
        { name: 'secret_ref', label: 'Shared Secret Reference', placeholder: 'env:AEGIS_BRANCH_AP_SECRET or file:branch-ap.secret' },
        { name: 'nas_type', label: 'NAS Type / Vendor Profile', placeholder: 'other, aruba, cisco, juniper, cambium, tplink' },
        { name: 'radsec_certificate_cn', label: 'RadSec Client Certificate CN', placeholder: 'nas01.example.net' },
        { name: 'radsec_certificate_issuer', label: 'RadSec Certificate Issuer DN', placeholder: 'Optional exact issuer DN' },
        {
          name: 'radsec_radius_v11',
          label: 'RADIUS/1.1 Policy',
          type: 'select',
          defaultValue: 'forbid',
          options: [
            { value: 'forbid', label: 'RADIUS/1.0 only' },
            { value: 'allow', label: 'Allow RADIUS/1.1' },
            { value: 'require', label: 'Require RADIUS/1.1' },
          ],
        },
        { name: 'description', label: 'Description', type: 'textarea' },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', defaultValue: true },
      ]}
    />
  );
}
