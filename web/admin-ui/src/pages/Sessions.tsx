import { useEffect, useMemo, useState } from 'react';
import api from '../api/client';

type LiveSession = {
  id: string;
  username: string;
  mac: string;
  ip: string;
  auth_method: string;
  vlan: number;
  start_time: string;
  last_activity?: string;
  end_time?: string;
  bytes_in: number;
  bytes_out: number;
};

type SessionAnalyticsCount = {
  name: string;
  count: number;
};

type SessionAnalyticsBucket = {
  start: string;
  end: string;
  started_count: number;
  ended_count: number;
  ended_traffic_total: number;
  ended_session_seconds_total: number;
};

type SessionAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  started_count: number;
  ended_count: number;
  active_now: number;
  unique_users_window: number;
  unique_macs_window: number;
  unique_ips_window: number;
  ended_traffic_total: number;
  ended_session_seconds_total: number;
  avg_ended_session_seconds: number;
  max_ended_session_seconds: number;
  longest_active_session_seconds: number;
  peak_concurrent_sessions: number;
  latest_start_at?: string;
  latest_end_at?: string;
  auth_methods: SessionAnalyticsCount[];
  roles: SessionAnalyticsCount[];
  vlans: SessionAnalyticsCount[];
  buckets: SessionAnalyticsBucket[];
};

type SessionAnalyticsPayload = {
  generated_at: string;
  username: string;
  auth_method: string;
  window_hours: number;
  bucket_count: number;
  summary: SessionAnalyticsSummary;
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return '0m';
  }
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function formatTimestamp(value?: string) {
  if (!value) {
    return 'Not recorded';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function StatusPill({ active }: { active: boolean }) {
  return (
    <span className={`rounded-md px-2 py-1 text-xs font-medium ${active ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-700'}`}>
      {active ? 'Active' : 'Ended'}
    </span>
  );
}

function StatCard({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-md border border-gray-200 px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-gray-900">{value}</div>
      <div className="mt-1 text-sm text-gray-600">{hint}</div>
    </div>
  );
}

function MixList({ title, items, empty }: { title: string; items: SessionAnalyticsCount[]; empty: string }) {
  return (
    <section className="rounded-lg bg-white p-6 shadow">
      <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
      <div className="mt-4 space-y-2">
        {items.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">{empty}</div>
        ) : (
          items.map((item) => (
            <div key={item.name} className="flex items-center justify-between rounded-md border border-gray-200 px-4 py-3 text-sm">
              <span className="text-gray-700">{item.name}</span>
              <span className="font-semibold text-gray-900">{item.count}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

export default function Sessions() {
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [analytics, setAnalytics] = useState<SessionAnalyticsSummary | null>(null);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [busyAction, setBusyAction] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [windowHours, setWindowHours] = useState(24);

  const bucketCount = useMemo(() => (windowHours <= 24 ? windowHours : 24), [windowHours]);

  const fetchSessions = async (announce = false) => {
    if (announce) {
      setError('');
      setMessage('');
    }
    setLoadingSessions(true);
    try {
      const { data } = await api.get('/sessions');
      setSessions(Array.isArray(data) ? data : []);
      if (announce) {
        setMessage('Live sessions refreshed.');
      }
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load sessions.');
    } finally {
      setLoadingSessions(false);
    }
  };

  const fetchAnalytics = async (announce = false) => {
    if (announce) {
      setError('');
      setMessage('');
    }
    setLoadingAnalytics(true);
    try {
      const { data } = await api.get<SessionAnalyticsPayload>(`/system/session-analytics?window_hours=${windowHours}&bucket_count=${bucketCount}`);
      setAnalytics(data.summary || null);
      if (announce) {
        setMessage('Session analytics refreshed.');
      }
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load session analytics.');
    } finally {
      setLoadingAnalytics(false);
    }
  };

  useEffect(() => {
    void fetchSessions(false);
    const interval = window.setInterval(() => {
      void fetchSessions(false);
    }, 10000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    void fetchAnalytics(false);
  }, [windowHours, bucketCount]);

  const terminateSession = async (id: string) => {
    if (!confirm('Terminate this session?')) return;
    setError('');
    setMessage('');
    setBusyAction(`terminate-${id}`);
    try {
      await api.delete(`/sessions/${id}`);
      setMessage('Session terminated.');
      await fetchSessions(false);
      await fetchAnalytics(false);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not terminate session.');
    } finally {
      setBusyAction('');
    }
  };

  const exportAnalytics = async (format: 'json' | 'csv') => {
    setError('');
    setMessage('');
    setBusyAction(`analytics-${format}`);
    try {
      const response = await api.get(`/system/session-analytics/export?format=${format}&window_hours=${windowHours}&bucket_count=${bucketCount}`, {
        responseType: 'blob',
      });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = format === 'json' ? 'aegisnas-session-analytics.json' : 'aegisnas-session-analytics.csv';
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Session analytics exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not export session analytics.');
    } finally {
      setBusyAction('');
    }
  };

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Sessions</h2>
          <p className="mt-1 text-sm text-gray-600">Watch live access activity, recent accounting outcomes, and the session mix over time from one place.</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <label className="text-sm text-gray-700">
            <span className="mb-1 block font-medium">Analytics Window</span>
            <select
              value={windowHours}
              onChange={(event) => setWindowHours(Number(event.target.value))}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm"
            >
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 72 hours</option>
            </select>
          </label>
          <div className="flex flex-wrap gap-3 self-end">
            <button onClick={() => void fetchSessions(true)} disabled={loadingSessions || busyAction !== ''} className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50">
              {loadingSessions ? 'Refreshing Live Sessions...' : 'Refresh Live Sessions'}
            </button>
            <button onClick={() => void fetchAnalytics(true)} disabled={loadingAnalytics || busyAction !== ''} className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800 disabled:opacity-50">
              {loadingAnalytics ? 'Refreshing Analytics...' : 'Refresh Analytics'}
            </button>
            <button onClick={() => void exportAnalytics('json')} disabled={busyAction !== ''} className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50">
              Export Analytics JSON
            </button>
            <button onClick={() => void exportAnalytics('csv')} disabled={busyAction !== ''} className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50">
              Export Analytics CSV
            </button>
          </div>
        </div>
      </div>

      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Session Activity Summary</h3>
            <p className="mt-1 text-sm text-gray-600">
              Started and ended session counts, peak concurrency, and ended-session traffic for the last {windowHours} hours.
            </p>
          </div>
          {analytics?.latest_start_at || analytics?.latest_end_at ? (
            <div className="text-xs text-gray-500">
              Latest start {formatTimestamp(analytics?.latest_start_at)}{analytics?.latest_end_at ? `, latest end ${formatTimestamp(analytics?.latest_end_at)}` : ''}
            </div>
          ) : null}
        </div>

        {loadingAnalytics ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading session analytics...</div>
        ) : !analytics ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">No session analytics available yet.</div>
        ) : (
          <>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <StatCard label="Active Now" value={analytics.active_now} hint="Sessions currently open on the appliance." />
              <StatCard label="Started" value={analytics.started_count} hint={`Sessions that began within the last ${analytics.window_hours} hours.`} />
              <StatCard label="Ended" value={analytics.ended_count} hint="Sessions with a completed stop record in the selected window." />
              <StatCard label="Peak Concurrent" value={analytics.peak_concurrent_sessions} hint="Highest overlapping active-session count during the window." />
              <StatCard label="Unique Users" value={analytics.unique_users_window} hint="Distinct usernames seen in the selected window." />
              <StatCard label="Ended Traffic" value={formatBytes(analytics.ended_traffic_total)} hint="Traffic on sessions that fully ended within the window." />
              <StatCard label="Average Ended Duration" value={formatDuration(analytics.avg_ended_session_seconds)} hint="Average duration across ended sessions in the window." />
              <StatCard label="Longest Active Session" value={formatDuration(analytics.longest_active_session_seconds)} hint="Current longest-running active session age." />
              <StatCard label="Unique Devices" value={analytics.unique_macs_window} hint="Distinct MAC addresses seen in the selected window." />
            </div>

            <div className="mt-6 grid gap-6 xl:grid-cols-3">
              <MixList title="Authentication Mix" items={analytics.auth_methods} empty="No authentication activity recorded in the selected window." />
              <MixList title="Role Mix" items={analytics.roles} empty="No role activity recorded in the selected window." />
              <MixList title="VLAN Mix" items={analytics.vlans} empty="No VLAN activity recorded in the selected window." />
            </div>
          </>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Session Activity Trend</h3>
          <p className="mt-1 text-sm text-gray-600">
            Bucketed starts, ends, and completed-session traffic over the selected window. Each bucket spans about {analytics?.bucket_minutes || Math.round((windowHours * 60) / bucketCount)} minutes.
          </p>
        </div>
        {loadingAnalytics ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading trend buckets...</div>
        ) : !analytics || analytics.buckets.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">No trend buckets available yet.</div>
        ) : (
          <div className="overflow-x-auto rounded-md border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {['Bucket', 'Started', 'Ended', 'Ended Traffic', 'Ended Duration'].map((label) => (
                    <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {analytics.buckets.map((bucket) => (
                  <tr key={`${bucket.start}-${bucket.end}`}>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      <div className="font-medium text-gray-900">{formatTimestamp(bucket.start)}</div>
                      <div className="text-xs text-gray-500">to {formatTimestamp(bucket.end)}</div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">{bucket.started_count}</td>
                    <td className="px-4 py-3 text-sm text-gray-700">{bucket.ended_count}</td>
                    <td className="px-4 py-3 text-sm text-gray-700">{formatBytes(bucket.ended_traffic_total)}</td>
                    <td className="px-4 py-3 text-sm text-gray-700">{formatDuration(bucket.ended_session_seconds_total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Live And Recent Sessions</h3>
            <p className="mt-1 text-sm text-gray-600">Most recent sessions from the appliance database, refreshed every 10 seconds while this page is open.</p>
          </div>
          <div className="text-xs text-gray-500">Showing the newest 100 session rows from the live table.</div>
        </div>
        <div className="overflow-x-auto rounded-md border border-gray-200">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {['User', 'IP', 'MAC', 'Auth', 'VLAN', 'Started', 'Last Activity', 'Status', 'Traffic', 'Actions'].map((label) => (
                  <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600">{label}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loadingSessions ? (
                <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={10}>Loading sessions...</td></tr>
              ) : sessions.length === 0 ? (
                <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={10}>No sessions found.</td></tr>
              ) : (
                sessions.map((session) => {
                  const active = !session.end_time;
                  return (
                    <tr key={session.id}>
                      <td className="px-4 py-3 text-sm text-gray-900">{session.username || 'Unknown user'}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{session.ip || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{session.mac || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{session.auth_method || 'unknown'}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{session.vlan || 0}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{formatTimestamp(session.start_time)}</td>
                      <td className="px-4 py-3 text-sm text-gray-700">{formatTimestamp(session.last_activity)}</td>
                      <td className="px-4 py-3 text-sm"><StatusPill active={active} /></td>
                      <td className="px-4 py-3 text-sm text-gray-700">{formatBytes(Number(session.bytes_in || 0) + Number(session.bytes_out || 0))}</td>
                      <td className="px-4 py-3 text-sm">
                        {active ? (
                          <button
                            onClick={() => void terminateSession(session.id)}
                            disabled={busyAction !== ''}
                            className="rounded-md bg-rose-700 px-3 py-1.5 text-white hover:bg-rose-800 disabled:opacity-50"
                          >
                            {busyAction === `terminate-${session.id}` ? 'Terminating...' : 'Terminate'}
                          </button>
                        ) : (
                          <span className="text-gray-400">Ended</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
