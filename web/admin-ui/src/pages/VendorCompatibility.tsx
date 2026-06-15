import { type ReactNode, useEffect, useMemo, useState } from 'react';
import api from '../api/client';

type VendorCompatibilitySummary = {
  product_vendor_id: number;
  product_vendor_name: string;
  product_attribute_count: number;
  semantic_count: number;
  pack_count: number;
  implemented_count: number;
  planned_count: number;
  hardware_profiles: string[];
};

type VendorProfileSummary = {
  total_clients: number;
  enabled_clients: number;
  profile_counts: Record<string, number>;
  unknown_profiles?: string[];
  global_fallback_client_count: number;
  known_vendor_profile_clients: number;
};

type VendorClientProfile = {
  shortname: string;
  ip: string;
  raw_nas_type?: string;
  nas_type: string;
  enabled: boolean;
  known_pack: boolean;
  uses_global_packs: boolean;
  effective_packs: string[];
  warning?: string;
};

type VendorPack = {
  key: string;
  label: string;
  vendor_name?: string;
  default_enabled: boolean;
  hardware_profiles: string[];
  notes?: string[];
};

type VendorSemanticCapability = {
  key: string;
  label: string;
  compatibility_state: string;
  next_step?: string;
  hardware_scope: string;
};

type VendorCompatibilityPayload = {
  summary: VendorCompatibilitySummary;
  active_packs?: string[];
  packs?: VendorPack[];
  client_profiles?: VendorClientProfile[];
  profile_summary?: VendorProfileSummary;
  semantics?: VendorSemanticCapability[];
  notes?: string[];
};

function StatCard({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-md border border-gray-200 px-4 py-3">
      <div className="text-xs font-semibold uppercase text-gray-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-gray-900">{value}</div>
      <div className="mt-1 text-sm text-gray-600">{hint}</div>
    </div>
  );
}

function StatusBadge({ tone, children }: { tone: 'green' | 'amber' | 'gray'; children: ReactNode }) {
  const classes = {
    green: 'bg-emerald-100 text-emerald-800',
    amber: 'bg-amber-100 text-amber-800',
    gray: 'bg-gray-100 text-gray-700',
  };
  return <span className={`rounded-md px-2 py-1 text-xs font-medium ${classes[tone]}`}>{children}</span>;
}

function joinList(values?: string[]) {
  if (!values || values.length === 0) {
    return 'None';
  }
  return values.join(', ');
}

export default function VendorCompatibility() {
  const [payload, setPayload] = useState<VendorCompatibilityPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const fetchCompatibility = async (announce = false) => {
    if (announce) {
      setError('');
      setMessage('');
    }
    setLoading(true);
    try {
      const { data } = await api.get<VendorCompatibilityPayload>('/system/vendor-compatibility');
      setPayload(data);
      if (announce) {
        setMessage('Vendor compatibility refreshed.');
      }
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load vendor compatibility.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchCompatibility(false);
  }, []);

  const clientProfiles = payload?.client_profiles || [];
  const profileSummary = payload?.profile_summary;
  const activePacks = payload?.active_packs || [];
  const packs = payload?.packs || [];
  const plannedSemantics = useMemo(
    () => (payload?.semantics || []).filter((item) => item.compatibility_state !== 'implemented'),
    [payload?.semantics],
  );
  const activePackDetails = useMemo(
    () => packs.filter((pack) => activePacks.includes(pack.key)),
    [packs, activePacks],
  );
  const profileCounts = Object.entries(profileSummary?.profile_counts || {}).sort(([left], [right]) => left.localeCompare(right));

  if (loading && !payload) {
    return <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading vendor compatibility...</div>;
  }

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Vendor Compatibility</h2>
          <p className="mt-1 text-sm text-gray-600">Confirm deployed NAS profiles, reply packs, and vendor dictionary coverage before changing access policy.</p>
        </div>
        <button
          onClick={() => void fetchCompatibility(true)}
          disabled={loading}
          className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      {payload ? (
        <>
          <section>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard label="Vendor" value={payload.summary.product_vendor_name || 'AegisNAS'} hint={`ID ${payload.summary.product_vendor_id || 0}`} />
              <StatCard label="Product VSAs" value={payload.summary.product_attribute_count || 0} hint="Built-in dictionary attributes." />
              <StatCard label="Active Packs" value={activePacks.length} hint={joinList(activePacks)} />
              <StatCard label="Client Profiles" value={profileSummary?.enabled_clients || 0} hint={`${profileSummary?.total_clients || 0} registered clients.`} />
              <StatCard label="Known Vendors" value={profileSummary?.known_vendor_profile_clients || 0} hint="Clients using a recognized pack." />
              <StatCard label="Global Fallback" value={profileSummary?.global_fallback_client_count || 0} hint="Clients using default compatibility packs." />
              <StatCard label="Implemented" value={payload.summary.implemented_count || 0} hint="Semantic capabilities ready now." />
              <StatCard label="Planned" value={payload.summary.planned_count || 0} hint="Compatibility capabilities still queued." />
            </div>
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">RADIUS Client Profiles</h3>
                <p className="mt-1 text-sm text-gray-600">Each enabled AP, controller, or switch should use the profile that matches the receiving device.</p>
              </div>
              {profileSummary?.unknown_profiles && profileSummary.unknown_profiles.length > 0 ? (
                <StatusBadge tone="amber">Fallback: {joinList(profileSummary.unknown_profiles)}</StatusBadge>
              ) : (
                <StatusBadge tone="green">Known profiles only</StatusBadge>
              )}
            </div>
            <div className="overflow-x-auto rounded-md border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Client', 'IP', 'NAS Type', 'Packs', 'Status', 'Warning'].map((label) => (
                      <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {clientProfiles.length === 0 ? (
                    <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={6}>No RADIUS clients found.</td></tr>
                  ) : (
                    clientProfiles.map((profile) => (
                      <tr key={`${profile.shortname}-${profile.ip}`}>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{profile.shortname || 'Unnamed client'}</div>
                          <div className="text-xs text-gray-500">{profile.enabled ? 'Enabled' : 'Disabled'}</div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{profile.ip || '-'}</td>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{profile.nas_type || 'other'}</div>
                          {profile.raw_nas_type ? <div className="text-xs text-gray-500">from {profile.raw_nas_type}</div> : null}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{joinList(profile.effective_packs)}</td>
                        <td className="px-4 py-3 text-sm">
                          {profile.known_pack ? (
                            <StatusBadge tone="green">Vendor pack</StatusBadge>
                          ) : profile.uses_global_packs ? (
                            <StatusBadge tone="amber">Global fallback</StatusBadge>
                          ) : (
                            <StatusBadge tone="gray">Custom</StatusBadge>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">{profile.warning || 'Ready'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <div className="mt-6 grid gap-6 xl:grid-cols-2">
            <section>
              <h3 className="text-lg font-semibold text-gray-900">Profile Mix</h3>
              <div className="mt-4 space-y-2">
                {profileCounts.length === 0 ? (
                  <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">No profile counts available.</div>
                ) : (
                  profileCounts.map(([profile, count]) => (
                    <div key={profile} className="flex items-center justify-between rounded-md border border-gray-200 px-4 py-3 text-sm">
                      <span className="font-medium text-gray-800">{profile}</span>
                      <span className="text-gray-600">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section>
              <h3 className="text-lg font-semibold text-gray-900">Active Reply Packs</h3>
              <div className="mt-4 space-y-2">
                {activePackDetails.length === 0 ? (
                  <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">No active reply packs configured.</div>
                ) : (
                  activePackDetails.map((pack) => (
                    <div key={pack.key} className="rounded-md border border-gray-200 px-4 py-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-medium text-gray-900">{pack.label}</span>
                        <span className="text-xs uppercase text-gray-500">{pack.key}</span>
                      </div>
                      <div className="mt-1 text-gray-600">{pack.vendor_name || 'Standards-based'} · {joinList(pack.hardware_profiles)}</div>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          <section className="mt-6">
            <h3 className="text-lg font-semibold text-gray-900">Planned Compatibility Work</h3>
            <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Capability', 'Scope', 'Next Step'].map((label) => (
                      <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {plannedSemantics.length === 0 ? (
                    <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={3}>No planned compatibility work listed.</td></tr>
                  ) : (
                    plannedSemantics.map((semantic) => (
                      <tr key={semantic.key}>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{semantic.label}</div>
                          <div className="text-xs text-gray-500">{semantic.key}</div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{semantic.hardware_scope}</td>
                        <td className="px-4 py-3 text-sm text-gray-700">{semantic.next_step || 'Queued'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      ) : (
        <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Vendor compatibility is unavailable.</div>
      )}
    </div>
  );
}
