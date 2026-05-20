import { useEffect, useState } from 'react';
import api from '../api/client';

type ReplicationManifest = {
  generated_at: string;
  source_node: string;
  source_role: string;
  schema_version: number;
  signature?: string;
  signature_algorithm?: string;
};

type StagedReplicationPackage = {
  id: string;
  imported_at: string;
  imported_by: string;
  imported_source?: string;
  activated_at?: string;
  activated_by?: string;
  ready: boolean;
  status: string;
  summary: string;
  config_valid: boolean;
  database_valid: boolean;
  network_state_present: boolean;
  package_checksum?: string;
  content_fingerprint?: string;
  encryption_algorithm?: string;
  encryption_status?: string;
  signature?: string;
  signature_algorithm?: string;
  signature_status?: string;
  activation_backup?: string;
  manifest: ReplicationManifest;
};

type SharedReplicationStatus = {
  present: boolean;
  package_path: string;
  metadata_path: string;
  published_at?: string;
  generated_at?: string;
  publish_mode?: string;
  source_node?: string;
  source_role?: string;
  schema_version?: number;
  package_size_bytes?: number;
  package_checksum?: string;
  content_fingerprint?: string;
  security_profile_hash?: string;
  encryption_algorithm?: string;
  encryption_status?: string;
  signature?: string;
  signature_algorithm?: string;
  signature_status?: string;
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

type UpgradeReadinessReport = {
  generated_at: string;
  config_path: string;
  database_path: string;
  database_exists: boolean;
  database_size_bytes: number;
  current_schema_version: number;
  target_schema_version: number;
  config_valid: boolean;
  config_validation_error?: string;
  deployment_profile?: string;
  deployment_form?: string;
  rehearsal: {
    ran: boolean;
    succeeded: boolean;
    started_schema_version: number;
    result_schema_version: number;
    duration_milliseconds: number;
    error?: string;
  };
  recommendations?: string[];
};

type UpgradeRollbackInspection = {
  manifest: {
    package_version: string;
    generated_at: string;
    config_path: string;
    database_path: string;
    current_schema_version: number;
    target_schema_version: number;
    deployment_profile?: string;
    deployment_form?: string;
    database_copy_mode: string;
    contains_secrets: boolean;
  };
  package_size_bytes: number;
  has_config_yaml: boolean;
  has_system_settings: boolean;
  has_database: boolean;
  current_runtime_schema_version: number;
  runtime_target_schema_version: number;
  config_valid: boolean;
  config_validation_error?: string;
  database_path_matches: boolean;
  compatibility_status: string;
  online_restore_supported: boolean;
  warnings?: string[];
  restore_steps?: string[];
  required_confirmation_text?: string;
};

type SupportBundleSummary = {
  bundle_version: string;
  generated_at: string;
  config_path: string;
  database_path: string;
  deployment_profile?: string;
  deployment_form?: string;
  ha_role?: string;
  contains_secrets: boolean;
  redaction_note: string;
  archive_entries: string[];
  api_captures: string[];
  runtime_entries: string[];
  system_captures: string[];
  log_captures: string[];
  upgrade_diagnostics: string[];
};

export default function Backups() {
  const [configFile, setConfigFile] = useState<File | null>(null);
  const [replicationFile, setReplicationFile] = useState<File | null>(null);
  const [upgradeRollbackFile, setUpgradeRollbackFile] = useState<File | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [stagedPackages, setStagedPackages] = useState<StagedReplicationPackage[]>([]);
  const [sharedStatus, setSharedStatus] = useState<SharedReplicationStatus | null>(null);
  const [haHistory, setHAHistory] = useState<HAHistoryRecord[]>([]);
  const [haHistoryStats, setHAHistoryStats] = useState<HAHistoryStats | null>(null);
  const [upgradeReadiness, setUpgradeReadiness] = useState<UpgradeReadinessReport | null>(null);
  const [upgradeRollbackInspection, setUpgradeRollbackInspection] = useState<UpgradeRollbackInspection | null>(null);
  const [supportBundleSummary, setSupportBundleSummary] = useState<SupportBundleSummary | null>(null);
  const [loadingStages, setLoadingStages] = useState(true);
  const [loadingSharedStatus, setLoadingSharedStatus] = useState(true);
  const [loadingHAHistory, setLoadingHAHistory] = useState(true);
  const [loadingUpgradeReadiness, setLoadingUpgradeReadiness] = useState(false);
  const [loadingUpgradeRollbackInspect, setLoadingUpgradeRollbackInspect] = useState(false);
  const [loadingSupportBundleSummary, setLoadingSupportBundleSummary] = useState(false);
  const [upgradeRollbackConfirmationText, setUpgradeRollbackConfirmationText] = useState('');
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
    void loadSupportBundleSummary();
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
      const response = await api.get('/system/ha/replication-package', { responseType: 'blob' });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      const disposition = `${headers?.['content-disposition'] || ''}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || 'aegisnas-ha-replication.pkg';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('HA replication package downloaded. Import it on the standby appliance, then activate it there.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not download HA replication package.');
    } finally {
      setBusyAction('');
    }
  };

  const downloadSupportBundle = async () => {
    setError('');
    setMessage('');
    setBusyAction('support-bundle');
    try {
      const response = await api.get('/system/support-bundle', { responseType: 'blob' });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      const disposition = `${headers?.['content-disposition'] || ''}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || 'aegisnas-support-bundle.zip';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('Support bundle downloaded. It includes redacted settings, runtime health, network and HA history, plus best-effort service diagnostics.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not download support bundle.');
    } finally {
      setBusyAction('');
    }
  };

  const loadSupportBundleSummary = async () => {
    setLoadingSupportBundleSummary(true);
    try {
      const { data } = await api.get('/system/support-bundle/summary');
      setSupportBundleSummary(data);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load support bundle summary.');
    } finally {
      setLoadingSupportBundleSummary(false);
    }
  };

  const downloadOpenAPISchema = async () => {
    setError('');
    setMessage('');
    setBusyAction('openapi-schema');
    try {
      const response = await api.get('/openapi.json', { responseType: 'blob' });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      const disposition = `${headers?.['content-disposition'] || ''}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || 'aegisnas-admin-api-openapi.json';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('Admin API OpenAPI schema downloaded. It includes endpoint groups, bearer-auth requirements, and AegisNAS role hints.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not download the OpenAPI schema.');
    } finally {
      setBusyAction('');
    }
  };

  const loadUpgradeReadiness = async () => {
    setError('');
    setLoadingUpgradeReadiness(true);
    try {
      const { data } = await api.get('/system/upgrade-readiness');
      setUpgradeReadiness(data);
      setMessage('Upgrade readiness refreshed.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load upgrade readiness.');
    } finally {
      setLoadingUpgradeReadiness(false);
    }
  };

  const downloadUpgradeRollbackPackage = async () => {
    setError('');
    setMessage('');
    setBusyAction('upgrade-rollback-package');
    try {
      const response = await api.get('/system/upgrade-rollback-package', { responseType: 'blob' });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      const disposition = `${headers?.['content-disposition'] || ''}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || 'aegisnas-upgrade-rollback.zip';
      link.click();
      URL.revokeObjectURL(url);
      setMessage('Upgrade rollback package downloaded. It contains a live config copy and a consistent database snapshot, so store it like credentials.');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not download upgrade rollback package.');
    } finally {
      setBusyAction('');
    }
  };

  const inspectUpgradeRollbackPackage = async () => {
    if (!upgradeRollbackFile) return;
    setError('');
    setMessage('');
    setLoadingUpgradeRollbackInspect(true);
    try {
      const form = new FormData();
      form.append('package', upgradeRollbackFile);
      const { data } = await api.post('/system/upgrade-rollback-package/inspect', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setUpgradeRollbackInspection(data.inspection || null);
      setUpgradeRollbackConfirmationText('');
      setMessage(`Rollback package ${data.filename || upgradeRollbackFile.name} inspected.`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not inspect upgrade rollback package.');
      setUpgradeRollbackInspection(null);
    } finally {
      setLoadingUpgradeRollbackInspect(false);
    }
  };

  const restoreUpgradeRollbackPackage = async () => {
    if (!upgradeRollbackFile || !upgradeRollbackInspection) return;
    if (!confirm('Restore this upgrade rollback package onto the appliance? A safety rollback package will be captured first.')) return;
    setError('');
    setMessage('');
    setBusyAction('upgrade-rollback-restore');
    try {
      const form = new FormData();
      form.append('package', upgradeRollbackFile);
      form.append('confirmation_text', upgradeRollbackConfirmationText);
      const { data } = await api.post('/system/upgrade-rollback-package/restore', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage(`Upgrade rollback package restored. Safety package saved at ${data.safety_package_path}.${data.restart_required ? ' Restart the appliance services before continuing.' : ''}`);
      window.dispatchEvent(new Event('config-applied'));
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not restore upgrade rollback package.');
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
                {sharedStatus.publish_mode ? ` Publish mode ${sharedStatus.publish_mode}.` : ''}
                {sharedStatus.schema_version ? ` Schema v${sharedStatus.schema_version}.` : ''}
                {sharedStatus.encryption_status ? ` Encryption ${sharedStatus.encryption_status}${sharedStatus.encryption_algorithm ? ` via ${sharedStatus.encryption_algorithm}` : ''}.` : ''}
                {sharedStatus.signature_status ? ` Signature ${sharedStatus.signature_status}.` : ''}
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
            <input type="file" accept=".pkg,.tar.gz,application/octet-stream,application/gzip,application/x-gzip" onChange={(event) => setReplicationFile(event.target.files?.[0] ?? null)} className="max-w-full text-sm" />
            <button disabled={!replicationFile || busyAction !== ''} onClick={uploadReplicationPackage} className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50">Stage On This Node</button>
            <button disabled={busyAction !== '' || !sharedStatus?.present} onClick={stageLatestSharedPackage} className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50">Stage Latest Shared Package</button>
          </div>
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            Activation keeps the <span className="font-medium">local HA role, peer URL, and database path</span> so the standby does not accidentally impersonate the active node’s identity.
          </div>
        </section>
      </div>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Support Bundle</h3>
            <p className="mt-1 text-sm text-gray-600">Capture a downloadable operator bundle with redacted settings, runtime status, HA and network history, and best-effort service logs for troubleshooting.</p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button onClick={() => void downloadOpenAPISchema()} disabled={busyAction !== ''} className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800 disabled:opacity-50">
              Download OpenAPI JSON
            </button>
            <button onClick={() => void downloadSupportBundle()} disabled={busyAction !== ''} className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50">
              Download Support Bundle
            </button>
          </div>
        </div>
        <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
          The OpenAPI schema documents the admin API surface, bearer-auth requirements, and role hints so integrations and runbooks can target the same contract the appliance is serving right now.
        </div>
        <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
          {loadingSupportBundleSummary ? (
            <span>Loading support bundle summary...</span>
          ) : supportBundleSummary ? (
            <div className="space-y-2">
              <div>
                Bundle v<span className="font-medium">{supportBundleSummary.bundle_version}</span> for {supportBundleSummary.deployment_profile || 'unknown'} / {supportBundleSummary.deployment_form || 'unknown'}
                {supportBundleSummary.ha_role ? ` with HA role ${supportBundleSummary.ha_role}` : ''}.
              </div>
              <div>{supportBundleSummary.redaction_note}</div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">API captures</div>
                  <div className="mt-1 font-semibold text-slate-900">{supportBundleSummary.api_captures.length}</div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">System captures</div>
                  <div className="mt-1 font-semibold text-slate-900">{supportBundleSummary.system_captures.length}</div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Log captures</div>
                  <div className="mt-1 font-semibold text-slate-900">{supportBundleSummary.log_captures.length}</div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Archive entries</div>
                  <div className="mt-1 font-semibold text-slate-900">{supportBundleSummary.archive_entries.length}</div>
                </div>
              </div>
              <div className="text-xs text-slate-500">
                Upgrade diagnostics included: {supportBundleSummary.upgrade_diagnostics.join(', ')}
              </div>
            </div>
          ) : (
            <span>Support bundle summary is not available yet.</span>
          )}
        </div>
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Upgrade Readiness</h3>
            <p className="mt-1 text-sm text-gray-600">Rehearse database migration on a temporary copy, compare schema versions, and catch upgrade blockers before touching the live appliance.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void loadUpgradeReadiness()} disabled={loadingUpgradeReadiness || busyAction !== ''} className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50">
              {loadingUpgradeReadiness ? 'Checking...' : 'Run Upgrade Readiness'}
            </button>
            <button onClick={() => void downloadUpgradeRollbackPackage()} disabled={busyAction !== ''} className="rounded-md border border-gray-300 px-4 py-2 text-gray-800 hover:bg-gray-50 disabled:opacity-50">
              Download Rollback Package
            </button>
          </div>
        </div>

        {!upgradeReadiness ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Run the readiness check to compare the current database schema, validate config, and rehearse migrations safely on a temporary copy.</div>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Schema</div>
                <div className="mt-2">Current v{upgradeReadiness.current_schema_version}, target v{upgradeReadiness.target_schema_version}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Config</div>
                <div className="mt-2">{upgradeReadiness.config_valid ? 'Valid' : 'Needs attention'}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Database</div>
                <div className="mt-2">{upgradeReadiness.database_exists ? `${upgradeReadiness.database_size_bytes} bytes` : 'Missing'}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Migration Rehearsal</div>
                <div className="mt-2">{upgradeReadiness.rehearsal.ran ? (upgradeReadiness.rehearsal.succeeded ? 'Passed' : 'Failed') : 'Not run'}</div>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div><span className="font-medium text-slate-900">Config path:</span> {upgradeReadiness.config_path}</div>
              <div className="mt-1"><span className="font-medium text-slate-900">Database path:</span> {upgradeReadiness.database_path}</div>
              <div className="mt-1"><span className="font-medium text-slate-900">Deployment:</span> {upgradeReadiness.deployment_profile || 'unknown'} / {upgradeReadiness.deployment_form || 'unknown'}</div>
              {upgradeReadiness.config_validation_error ? (
                <div className="mt-2 text-red-700"><span className="font-medium">Validation error:</span> {upgradeReadiness.config_validation_error}</div>
              ) : null}
              {upgradeReadiness.rehearsal.error ? (
                <div className="mt-2 text-red-700"><span className="font-medium">Rehearsal error:</span> {upgradeReadiness.rehearsal.error}</div>
              ) : null}
              {upgradeReadiness.rehearsal.ran ? (
                <div className="mt-2">
                  Started on schema v{upgradeReadiness.rehearsal.started_schema_version}, ended on v{upgradeReadiness.rehearsal.result_schema_version} in {upgradeReadiness.rehearsal.duration_milliseconds} ms.
                </div>
              ) : null}
            </div>

            {upgradeReadiness.recommendations && upgradeReadiness.recommendations.length > 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                <div className="font-medium">Recommendations</div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {upgradeReadiness.recommendations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Rollback Package Restore</h3>
            <p className="mt-1 text-sm text-gray-600">Inspect an upgrade rollback package first, then restore it only when the runtime says online restore is supported for this schema and path context.</p>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <input type="file" accept=".zip,application/zip" onChange={(event) => setUpgradeRollbackFile(event.target.files?.[0] ?? null)} className="max-w-full text-sm" />
          <button disabled={!upgradeRollbackFile || loadingUpgradeRollbackInspect || busyAction !== ''} onClick={() => void inspectUpgradeRollbackPackage()} className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50">
            {loadingUpgradeRollbackInspect ? 'Inspecting...' : 'Inspect Rollback Package'}
          </button>
        </div>

        {!upgradeRollbackInspection ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Choose a rollback package zip and inspect it before any restore action.</div>
        ) : (
          <div className="mt-4 space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Compatibility</div>
                <div className="mt-2">{upgradeRollbackInspection.compatibility_status}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Schema</div>
                <div className="mt-2">Package v{upgradeRollbackInspection.manifest.current_schema_version} to runtime target v{upgradeRollbackInspection.runtime_target_schema_version}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Config Validation</div>
                <div className="mt-2">{upgradeRollbackInspection.config_valid ? 'Valid' : 'Failed'}</div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Online Restore</div>
                <div className="mt-2">{upgradeRollbackInspection.online_restore_supported ? 'Supported' : 'Offline required'}</div>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div><span className="font-medium text-slate-900">Config path:</span> {upgradeRollbackInspection.manifest.config_path || 'unknown'}</div>
              <div className="mt-1"><span className="font-medium text-slate-900">Database path:</span> {upgradeRollbackInspection.manifest.database_path || 'unknown'}</div>
              <div className="mt-1"><span className="font-medium text-slate-900">Contents:</span> config YAML {upgradeRollbackInspection.has_config_yaml ? 'present' : 'missing'}, system settings {upgradeRollbackInspection.has_system_settings ? 'present' : 'missing'}, database {upgradeRollbackInspection.has_database ? 'present' : 'missing'}</div>
              <div className="mt-1"><span className="font-medium text-slate-900">Database path match:</span> {upgradeRollbackInspection.database_path_matches ? 'yes' : 'no'}</div>
              {upgradeRollbackInspection.config_validation_error ? (
                <div className="mt-2 text-red-700"><span className="font-medium">Validation error:</span> {upgradeRollbackInspection.config_validation_error}</div>
              ) : null}
            </div>

            {upgradeRollbackInspection.warnings && upgradeRollbackInspection.warnings.length > 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                <div className="font-medium">Warnings</div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {upgradeRollbackInspection.warnings.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            {upgradeRollbackInspection.restore_steps && upgradeRollbackInspection.restore_steps.length > 0 ? (
              <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Restore Steps</div>
                <ol className="mt-2 list-decimal space-y-1 pl-5">
                  {upgradeRollbackInspection.restore_steps.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              </div>
            ) : null}

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div className="font-medium text-slate-900">Confirm Restore</div>
              <p className="mt-1">Type <span className="font-mono">{upgradeRollbackInspection.required_confirmation_text || 'RESTORE UPGRADE ROLLBACK'}</span> to allow the restore action.</p>
              <input
                value={upgradeRollbackConfirmationText}
                onChange={(event) => setUpgradeRollbackConfirmationText(event.target.value)}
                className="mt-3 w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900"
                placeholder={upgradeRollbackInspection.required_confirmation_text || 'RESTORE UPGRADE ROLLBACK'}
              />
              <div className="mt-3">
                <button
                  disabled={
                    busyAction !== '' ||
                    !upgradeRollbackInspection.online_restore_supported ||
                    upgradeRollbackConfirmationText !== (upgradeRollbackInspection.required_confirmation_text || 'RESTORE UPGRADE ROLLBACK')
                  }
                  onClick={() => void restoreUpgradeRollbackPackage()}
                  className="rounded-md bg-amber-700 px-4 py-2 text-white hover:bg-amber-800 disabled:opacity-50"
                >
                  Restore From Rollback Package
                </button>
              </div>
            </div>
          </div>
        )}
      </section>

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
                    {pkg.imported_source ? <div className="mt-1 text-xs text-gray-500">Imported via {pkg.imported_source}.</div> : null}
                    {pkg.package_checksum ? <div className="mt-1 text-xs text-gray-500 break-all">Archive checksum {pkg.package_checksum}</div> : null}
                    {pkg.content_fingerprint ? <div className="mt-1 text-xs text-gray-500 break-all">Content fingerprint {pkg.content_fingerprint}</div> : null}
                    {pkg.encryption_status ? <div className="mt-1 text-xs text-gray-500">Encryption {pkg.encryption_status}{pkg.encryption_algorithm ? ` via ${pkg.encryption_algorithm}` : ''}.</div> : null}
                    {pkg.signature_status ? <div className="mt-1 text-xs text-gray-500">Signature {pkg.signature_status}{pkg.signature_algorithm ? ` via ${pkg.signature_algorithm}` : ''}.</div> : null}
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
