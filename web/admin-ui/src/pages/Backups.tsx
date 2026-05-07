import { useEffect, useState } from 'react';
import api from '../api/client';

type ReplicationManifest = {
  generated_at: string;
  source_node: string;
  source_role: string;
  schema_version: number;
};

type StagedReplicationPackage = {
  id: string;
  imported_at: string;
  imported_by: string;
  activated_at?: string;
  activated_by?: string;
  ready: boolean;
  status: string;
  summary: string;
  config_valid: boolean;
  database_valid: boolean;
  network_state_present: boolean;
  activation_backup?: string;
  manifest: ReplicationManifest;
};

type SharedReplicationStatus = {
  present: boolean;
  package_path: string;
  metadata_path: string;
  published_at?: string;
  generated_at?: string;
  source_node?: string;
  source_role?: string;
  schema_version?: number;
  package_size_bytes?: number;
  package_checksum?: string;
  network_state_present?: boolean;
};

type HAHistoryRecord = {
  id: number;
  event_type: string;
  status: string;
  summary: string;
  node_role?: string;
  actor?: string;
  details?: Record<string, any>;
  created_at: string;
};

type HAHistoryStats = {
  total_records: number;
  failover_promotions: number;
  failover_returns: number;
  peer_failures: number;
  peer_recoveries: number;
  vip_acquisitions: number;
  vip_preemptions: number;
  vip_releases: number;
  replication_publishes: number;
  replication_failures: number;
  replication_stale_count: number;
  shared_stages: number;
  activations: number;
  last_event_at?: string;
};

export default function Backups() {
  const [configFile, setConfigFile] = useState<File | null>(null);
  const [replicationFile, setReplicationFile] = useState<File | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [stagedPackages, setStagedPackages] = useState<StagedReplicationPackage[]>([]);
  const [sharedStatus, setSharedStatus] = useState<SharedReplicationStatus | null>(null);
  const [haHistory, setHAHistory] = useState<HAHistoryRecord[]>([]);
  const [haHistoryStats, setHAHistoryStats] = useState<HAHistoryStats | null>(null);
  const [loadingStages, setLoadingStages] = useState(true);
  const [loadingSharedStatus, setLoadingSharedStatus] = useState(true);
  const [loadingHAHistory, setLoadingHAHistory] = useState(true);
  const [busyAction, setBusyAction] = useState('');

  const loadStages = async () => {
    setLoadingStages(true);
    try {
      const { data } = await api.get('/system/ha/replication-staged');
      setStagedPackages(data.packages || []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load staged replication packages.');
    } finally {
      setLoadingStages(false);
    }
  };

  const loadSharedStatus = async () => {
    setLoadingSharedStatus(true);
    try {
      const { data } = await api.get('/system/ha/replication-shared');
      setSharedStatus(data.shared || null);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load shared HA replication status.');
    } finally {
      setLoadingSharedStatus(false);
    }
  };

  const loadHAHistory = async () => {
    setLoadingHAHistory(true);
    try {
      const { data } = await api.get('/system/ha/history');
      setHAHistory(data.history || []);
      setHAHistoryStats(data.stats || null);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load HA history.');
    } finally {
      setLoadingHAHistory(false);
    }
  };

  useEffect(() => {
    void loadStages();
    void loadSharedStatus();
    void loadHAHistory();
  }, []);

  const downloadConfigBackup = async () => {
    setError('');
    setMessage('');
    try {
      const { data } = await api.get('/backups/config', { responseType: 'blob' });
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'aegisnas-config-backup.json';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('Config JSON backup downloaded.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Download failed.');
    }
  };

  const uploadConfigBackup = async () => {
    if (!configFile) return;
    if (!confirm('Restore this config JSON? A safety revision will be created first.')) return;
    setError('');
    setMessage('');
      setBusyAction('config-restore');
    try {
      await api.post('/backups/config', await configFile.text(), { headers: { 'Content-Type': 'application/json' } });
      setMessage('Config JSON restored.');
      window.dispatchEvent(new Event('config-applied'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Upload failed.');
    } finally {
      setBusyAction('');
    }
  };

  const downloadReplicationPackage = async () => {
    setError('');
    setMessage('');
    setBusyAction('replication-download');
    try {
      const { data } = await api.get('/system/ha/replication-package', { responseType: 'blob' });
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'aegisnas-ha-replication.tar.gz';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('HA replication package downloaded. Import it on the standby appliance, then activate it there.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not download HA replication package.');
    } finally {
      setBusyAction('');
    }
  };

  const uploadReplicationPackage = async () => {
    if (!replicationFile) return;
    setError('');
    setMessage('');
    setBusyAction('replication-upload');
    try {
      const form = new FormData();
      form.append('package', replicationFile);
      const { data } = await api.post('/system/ha/replication-package', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage(`Replication package ${data.package?.id || ''} is staged and validated on this node.`);
      await loadStages();
      await loadHAHistory();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not stage HA replication package.');
    } finally {
      setBusyAction('');
    }
  };

  const stageLatestSharedPackage = async () => {
    if (!confirm('Stage the latest shared HA package on this node? This is intended for the standby appliance before activation.')) return;
    setError('');
    setMessage('');
    setBusyAction('replication-stage-shared');
    try {
      const { data } = await api.post('/system/ha/replication-stage-shared', {});
      setMessage(data.message || `Shared replication package ${data.package?.id || ''} is staged on this node.`);
      await loadStages();
      await loadSharedStatus();
      await loadHAHistory();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not stage the latest shared HA replication package.');
    } finally {
      setBusyAction('');
    }
  };

  const activateReplicationPackage = async (pkg: StagedReplicationPackage) => {
    if (!confirm(`Activate staged package ${pkg.id}? This is intended for standby appliances and will restart services after local safety backup capture.`)) return;
    setError('');
    setMessage('');
    setBusyAction(`activate-${pkg.id}`);
    try {
      const { data } = await api.post('/system/ha/replication-activate', { id: pkg.id });
      setMessage(data.message || `Replication package ${pkg.id} was activated and service restart was scheduled.`);
      await loadStages();
      await loadSharedStatus();
      await loadHAHistory();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not activate staged HA replication package.');
    } finally {
      setBusyAction('');
    }
  };

  const exportHAHistory = async (format: 'csv' | 'json') => {
    setError('');
    setMessage('');
    try {
      const response = await api.get(`/system/ha/history/export?format=${format}`, { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = format === 'json' ? 'aegisnas-ha-history.json' : 'aegisnas-ha-history.csv';
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`HA history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not export HA history.');
    }
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Backups</h2>
      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <div className="grid gap-6 xl:grid-cols-2">
        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">Config Snapshot</h3>
          <p className="mb-4 text-sm text-gray-600">Export or restore the admin-managed JSON config snapshot for users, vouchers, roles, profiles, policies, identity sources, and RADIUS clients.</p>
          <div className="flex flex-wrap gap-3">
            <button onClick={downloadConfigBackup} disabled={busyAction !== ''} className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800 disabled:opacity-50">Download JSON</button>
            <input type="file" accept="application/json,.json" onChange={(event) => setConfigFile(event.target.files?.[0] ?? null)} className="max-w-full text-sm" />
            <button disabled={!configFile || busyAction !== ''} onClick={uploadConfigBackup} className="rounded-md bg-amber-700 px-4 py-2 text-white hover:bg-amber-800 disabled:opacity-50">Upload And Restore</button>
          </div>
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            {loadingSharedStatus ? (
              <span>Loading shared HA replication status...</span>
            ) : sharedStatus?.present ? (
              <span>
                Latest shared package from <span className="font-medium">{sharedStatus.source_node || 'unknown'}</span>
                {sharedStatus.published_at ? ` published ${sharedStatus.published_at}` : ''}.
                {sharedStatus.schema_version ? ` Schema v${sharedStatus.schema_version}.` : ''}
              </span>
            ) : (
              <span>No shared HA package has been published yet. The active node will create one during the continuous replication interval.</span>
            )}
          </div>
        </section>

        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">Standby Replication Package</h3>
          <p className="mb-4 text-sm text-gray-600">Package the live config, database, and managed network state from the active appliance, then stage and activate that package on a standby peer.</p>
          <div className="flex flex-wrap gap-3">
            <button onClick={downloadReplicationPackage} disabled={busyAction !== ''} className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50">Download HA Package</button>
            <input type="file" accept=".tar.gz,application/gzip,application/x-gzip" onChange={(event) => setReplicationFile(event.target.files?.[0] ?? null)} className="max-w-full text-sm" />
            <button disabled={!replicationFile || busyAction !== ''} onClick={uploadReplicationPackage} className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50">Stage On This Node</button>
            <button disabled={busyAction !== '' || !sharedStatus?.present} onClick={stageLatestSharedPackage} className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50">Stage Latest Shared Package</button>
          </div>
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            Activation keeps the <span className="font-medium">local HA role, peer URL, and database path</span> so the standby does not accidentally impersonate the active node’s identity.
          </div>
        </section>
      </div>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Staged HA Packages</h3>
            <p className="mt-1 text-sm text-gray-600">Import on the standby, validate the package, then activate it to lay down the replicated config and database before the service restart.</p>
          </div>
          <button onClick={() => { void loadStages(); void loadSharedStatus(); }} disabled={loadingStages || busyAction !== ''} className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
            Refresh
          </button>
        </div>

        {loadingStages ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading staged replication packages...</div>
        ) : stagedPackages.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">No staged HA packages yet. Download a package from the active node, then upload it here.</div>
        ) : (
          <div className="space-y-4">
            {stagedPackages.map((pkg) => (
              <div key={pkg.id} className="rounded-md border border-gray-200 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-gray-900">{pkg.id}</div>
                    <div className="mt-1 text-sm text-gray-600">{pkg.summary}</div>
                    <div className="mt-2 text-xs text-gray-500">
                      Imported {pkg.imported_at} by {pkg.imported_by}. Source: {pkg.manifest?.source_node || 'unknown'} ({pkg.manifest?.source_role || 'unknown'}).
                    </div>
                    {pkg.activation_backup ? <div className="mt-1 text-xs text-gray-500">Safety backup: {pkg.activation_backup}</div> : null}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full px-3 py-1 text-xs font-medium ${pkg.status === 'activated' ? 'bg-emerald-100 text-emerald-800' : pkg.ready ? 'bg-sky-100 text-sky-800' : 'bg-amber-100 text-amber-800'}`}>
                      {pkg.status}
                    </span>
                    <button
                      disabled={!pkg.ready || busyAction !== ''}
                      onClick={() => void activateReplicationPackage(pkg)}
                      className="rounded-md bg-indigo-700 px-4 py-2 text-sm text-white hover:bg-indigo-800 disabled:opacity-50"
                    >
                      Activate On Standby
                    </button>
                  </div>
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">Schema Version</div>
                    <div className="mt-1">{pkg.manifest?.schema_version ?? 'unknown'}</div>
                  </div>
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">Validation</div>
                    <div className="mt-1">
                      Config {pkg.config_valid ? 'OK' : 'Failed'}, database {pkg.database_valid ? 'OK' : 'Failed'}, network state {pkg.network_state_present ? 'included' : 'not included'}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">Activation</div>
                    <div className="mt-1">{pkg.activated_at ? `Activated ${pkg.activated_at} by ${pkg.activated_by || 'unknown'}` : 'Not activated yet'}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">HA History</h3>
            <p className="mt-1 text-sm text-gray-600">Track failover promotions, peer health changes, VIP lease actions, and replication activity over time.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void loadHAHistory()} disabled={loadingHAHistory || busyAction !== ''} className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
              Refresh
            </button>
            <button onClick={() => void exportHAHistory('csv')} disabled={busyAction !== ''} className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
              Export CSV
            </button>
            <button onClick={() => void exportHAHistory('json')} disabled={busyAction !== ''} className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Failover Events</div>
            <div className="mt-2">Promotions {haHistoryStats?.failover_promotions ?? 0}, returns {haHistoryStats?.failover_returns ?? 0}</div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Peer Health</div>
            <div className="mt-2">Failures {haHistoryStats?.peer_failures ?? 0}, recoveries {haHistoryStats?.peer_recoveries ?? 0}</div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">VIP Lease</div>
            <div className="mt-2">Acquired {haHistoryStats?.vip_acquisitions ?? 0}, preempted {haHistoryStats?.vip_preemptions ?? 0}, released {haHistoryStats?.vip_releases ?? 0}</div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Replication</div>
            <div className="mt-2">Publishes {haHistoryStats?.replication_publishes ?? 0}, stale events {haHistoryStats?.replication_stale_count ?? 0}, activations {haHistoryStats?.activations ?? 0}</div>
          </div>
        </div>

        {loadingHAHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading HA history...</div>
        ) : haHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">No HA history recorded yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">When</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Event</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Status</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Role</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Actor</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {haHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">{item.created_at}</td>
                    <td className="px-3 py-2 text-gray-900">{item.event_type}</td>
                    <td className="px-3 py-2 text-gray-700">{item.status}</td>
                    <td className="px-3 py-2 text-gray-700">{item.node_role || '-'}</td>
                    <td className="px-3 py-2 text-gray-700">{item.actor || '-'}</td>
                    <td className="px-3 py-2 text-gray-700">{item.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
