import CrudPage from '../components/CrudPage';

export default function ACLPolicies() {
  return (
    <CrudPage
      title="ACL Policies"
      endpoint="/acl-policies"
      itemName="ACL Policy"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'enabled', label: 'Enabled', render: (item) => (item.enabled ? 'Yes' : 'No') },
        { key: 'inbound_acl', label: 'Inbound ACL' },
        { key: 'outbound_acl', label: 'Outbound ACL' },
        { key: 'rules', label: 'Rules', render: (item) => (Array.isArray(item.rules) ? item.rules.length : 0) },
        { key: 'ast_fingerprint', label: 'AST', render: (item) => (item.ast_fingerprint ? 'Ready' : 'Derived') },
        {
          key: 'acl_round_trip',
          label: 'Round Trip',
          render: (item) => (item.acl_round_trip?.lossless === false ? 'Diagnostics' : 'Lossless'),
        },
      ]}
      fields={[
        { name: 'name', label: 'Name', required: true },
        { name: 'description', label: 'Description', type: 'textarea' },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', defaultValue: true },
        { name: 'inbound_acl', label: 'Vendor Inbound ACL Name' },
        { name: 'outbound_acl', label: 'Vendor Outbound ACL Name' },
        {
          name: 'rules',
          label: 'Vendor-Neutral Rules JSON',
          type: 'json',
          required: true,
          defaultValue: '[\n  {\n    "action": "permit",\n    "direction": "in",\n    "protocol": "tcp",\n    "source": "any",\n    "destination": "any",\n    "destination_port": "443"\n  }\n]',
        },
        {
          name: 'acl_ast',
          label: 'ACL AST JSON',
          type: 'json',
          defaultValue: '{\n  "schema_version": 1,\n  "default_action": "deny",\n  "object_groups": [],\n  "service_groups": [],\n  "rules": []\n}',
        },
      ]}
    />
  );
}
