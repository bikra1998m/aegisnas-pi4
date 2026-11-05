import { useCallback, useEffect, useState } from 'react';
import api from '../api/client';

type ReleaseSecurityReport = {
  status: string;
  go_version: string;
  signature_reverified: boolean;
  signature_verified_at_admission: boolean;
  current_binary_matches_receipt: boolean;
  verified_at?: string;
  artifact_sha256?: string;
  release?: { repository: string; source_commit: string; platform: string; release_sequence: number };
  blockers: string[];
  scope: string;
};

const labels: Record<string, string> = {
  not_admitted: 'No verified admission recorded',
  invalid_receipt: 'Invalid admission record',
  integrity_mismatch: 'Installed binary does not match admission',
  admission_recorded: 'Admission recorded; API binary matches',
};

export default function ReleaseSecurity() {
  const [report, setReport] = useState<ReleaseSecurityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get<ReleaseSecurityReport>('/system/release-security');
      setReport(response.data);
    } catch {
      setReport(null);
      setError('Release security evidence could not be loaded. Verification state is unknown.');
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);

  return <section className="space-y-5 p-6">
    <div className="flex items-center justify-between">
      <h1 className="text-2xl font-bold text-gray-900">Release Security</h1>
      <button className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50" disabled={loading}
        onClick={() => void refresh()}>{loading ? 'Checking…' : 'Refresh evidence'}</button>
    </div>
    <p className="text-gray-600">Inspect the release admission record and the running API binary.</p>
    {error && <p role="alert" className="rounded border border-red-300 bg-red-50 p-4 text-red-800">{error}</p>}
    {report && <div className="space-y-4 rounded border bg-white p-5">
      <h2 className="text-lg font-semibold">{labels[report.status] || 'Unknown verification state'}</h2>
      <p>{report.scope}</p>
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <dt>Go runtime</dt><dd>{report.go_version}</dd>
        <dt>Signature check at admission</dt><dd>{report.signature_verified_at_admission ? 'Recorded' : 'Not recorded'}</dd>
        <dt>Current API binary checksum</dt><dd>{report.current_binary_matches_receipt ? 'Matches admission record' : 'Not confirmed'}</dd>
        <dt>Fresh signature verification</dt><dd>{report.signature_reverified ? 'Verified' : 'Not performed by this page'}</dd>
        {report.verified_at && <><dt>Admission time</dt><dd>{report.verified_at}</dd></>}
        {report.release && <>
          <dt>Repository</dt><dd>{report.release.repository}</dd>
          <dt>Source commit</dt><dd className="break-all font-mono">{report.release.source_commit}</dd>
          <dt>Platform</dt><dd>{report.release.platform}</dd>
          <dt>Release sequence</dt><dd>{report.release.release_sequence}</dd>
        </>}
        {report.artifact_sha256 && <><dt>Artifact SHA-256</dt><dd className="break-all font-mono">{report.artifact_sha256}</dd></>}
      </dl>
      {report.blockers.length > 0 && <ul className="list-disc space-y-1 pl-5 text-red-800">
        {report.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}
      </ul>}
    </div>}
  </section>;
}
