import { useEffect, useMemo, useState } from "react";
import api from "../api/client";

type GuestRegistrationRecord = {
  id: string;
  status: string;
  tenant?: string;
  full_name?: string;
  email?: string;
  phone?: string;
  company?: string;
  purpose?: string;
  sponsor_name?: string;
  sponsor_email?: string;
  sponsor_phone?: string;
  client_mac?: string;
  client_ip?: string;
  username?: string;
  role?: string;
  approved_by?: string;
  rejection_reason?: string;
  approval_delivery_status?: string;
  approval_delivery_error?: string;
  invite_delivery_status?: string;
  invite_delivery_error?: string;
  created_at?: string;
  updated_at?: string;
  approved_at?: string;
  rejected_at?: string;
  completed_at?: string;
  expires_at?: string;
};

type GuestLifecycleCount = {
  name: string;
  count: number;
};

type GuestLifecycleBucket = {
  start: string;
  end: string;
  submitted_count: number;
  approved_count: number;
  rejected_count: number;
  completed_count: number;
};

type GuestLifecycleSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  pending_count: number;
  approved_count: number;
  rejected_count: number;
  completed_count: number;
  sponsor_approval_required_count: number;
  approval_delivery_pending_count: number;
  approval_delivery_sent_count: number;
  approval_delivery_failed_count: number;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  unique_guests_window: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_approval_minutes: number;
  avg_completion_minutes: number;
  latest_submitted_at?: string;
  latest_approved_at?: string;
  latest_rejected_at?: string;
  latest_completed_at?: string;
  roles: GuestLifecycleCount[];
  buckets: GuestLifecycleBucket[];
};

type GuestLifecycleReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  count: number;
  history: GuestRegistrationRecord[];
  summary: GuestLifecycleSummary;
};

const statusOptions = [
  { value: "", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "completed", label: "Completed" },
];

function statusPillClass(status: string) {
  switch (status.toLowerCase()) {
    case "approved":
    case "completed":
      return "border border-emerald-200 bg-emerald-50 text-emerald-700";
    case "rejected":
      return "border border-red-200 bg-red-50 text-red-700";
    case "pending":
      return "border border-amber-200 bg-amber-50 text-amber-700";
    default:
      return "border border-slate-200 bg-slate-50 text-slate-600";
  }
}

function formatTimestamp(value?: string) {
  if (!value) {
    return "Not recorded";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export default function GuestRegistrations() {
  const [report, setReport] = useState<GuestLifecycleReport | null>(null);
  const [selectedStatus, setSelectedStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busyAction, setBusyAction] = useState("");

  const fetchReport = async (showMessage = false) => {
    try {
      setError("");
      const params = new URLSearchParams();
      if (selectedStatus) {
        params.set("status", selectedStatus);
      }
      params.set("limit", "200");
      const suffix = params.toString() ? `?${params.toString()}` : "";
      const { data } = await api.get(`/system/guest-lifecycle${suffix}`);
      setReport(data);
      if (showMessage) {
        setMessage("Guest lifecycle report refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest lifecycle report.",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchReport();
    const interval = window.setInterval(() => {
      fetchReport();
    }, 10000);
    return () => window.clearInterval(interval);
  }, [selectedStatus]);

  const approve = async (id: string) => {
    if (!window.confirm("Approve this guest request?")) {
      return;
    }
    setBusyAction(`approve-${id}`);
    try {
      await api.post(`/guest-registrations/${id}/approve`);
      setMessage("Guest request approved.");
      await fetchReport();
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not approve guest request.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const reject = async (id: string) => {
    const reason = window.prompt("Reject reason (optional):", "") ?? "";
    if (!window.confirm("Reject this guest request?")) {
      return;
    }
    setBusyAction(`reject-${id}`);
    try {
      await api.post(`/guest-registrations/${id}/reject`, { reason });
      setMessage("Guest request rejected.");
      await fetchReport();
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not reject guest request.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadExport = async (format: "json" | "csv") => {
    setBusyAction(`export-${format}`);
    try {
      const params = new URLSearchParams({ format });
      if (selectedStatus) {
        params.set("status", selectedStatus);
      }
      const response = await api.get(
        `/system/guest-lifecycle/export?${params.toString()}`,
        { responseType: "blob" },
      );
      const blob = new Blob([response.data], {
        type: format === "json" ? "application/json" : "text/csv;charset=utf-8",
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const filenameMatch = /filename="([^"]+)"/.exec(
        response.headers["content-disposition"] || "",
      );
      link.download =
        filenameMatch?.[1] || `aegisnas-guest-lifecycle.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      setMessage(`Guest lifecycle ${format.toUpperCase()} export downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export guest lifecycle report.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const records = report?.history || [];
  const summary = report?.summary;
  const recentBuckets = useMemo(
    () => (summary?.buckets || []).slice(-6),
    [summary],
  );

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Guest Registrations
          </h2>
          <p className="mt-1 text-sm text-gray-600">
            Track self-registration, sponsor approval, delivery outcomes, and
            recent lifecycle trends from one place.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => fetchReport(true)}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={() => downloadExport("json")}
            disabled={busyAction === "export-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Export JSON
          </button>
          <button
            type="button"
            onClick={() => downloadExport("csv")}
            disabled={busyAction === "export-csv"}
            className="rounded-md bg-sky-700 px-3 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Export CSV
          </button>
        </div>
      </div>

      {message ? (
        <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          {message}
        </div>
      ) : null}
      {error ? (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {String(error)}
        </div>
      ) : null}

      <div className="mb-6 flex flex-wrap items-end gap-4">
        <label className="flex min-w-[220px] flex-col gap-2 text-sm text-slate-700">
          <span className="font-medium text-slate-900">Status filter</span>
          <select
            value={selectedStatus}
            onChange={(event) => setSelectedStatus(event.target.value)}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
          >
            {statusOptions.map((option) => (
              <option key={option.value || "all"} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="text-sm text-slate-600">
          {report ? (
            <>
              <div>
                <span className="font-medium text-slate-900">Generated:</span>{" "}
                {formatTimestamp(report.generated_at)}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Window:</span>{" "}
                {report.window_hours} hours across {report.bucket_count} buckets
              </div>
            </>
          ) : (
            <div>Waiting for guest lifecycle data...</div>
          )}
        </div>
      </div>

      {!summary ? (
        <div className="rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
          {loading
            ? "Loading guest lifecycle report..."
            : "Guest lifecycle data is not available yet."}
        </div>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {[
              {
                label: "Pending",
                value: summary.pending_count,
                hint: `${summary.sponsor_approval_required_count} require sponsor delivery`,
              },
              {
                label: "Approved",
                value: summary.approved_count,
                hint: `${summary.invite_sent_count} invite deliveries sent`,
              },
              {
                label: "Rejected",
                value: summary.rejected_count,
                hint: `${summary.approval_delivery_failed_count} approval deliveries failed`,
              },
              {
                label: "Completed",
                value: summary.completed_count,
                hint: `${summary.avg_completion_minutes} minute average to completion`,
              },
            ].map((card) => (
              <div
                key={card.label}
                className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm"
              >
                <div className="text-sm font-medium text-slate-600">
                  {card.label}
                </div>
                <div className="mt-2 text-3xl font-semibold text-slate-900">
                  {card.value}
                </div>
                <div className="mt-2 text-xs text-slate-500">{card.hint}</div>
              </div>
            ))}
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Recent lifecycle trend
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Most recent {recentBuckets.length} buckets across the selected
                report window.
              </p>
              <div className="mt-4 overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200 text-sm">
                  <thead className="bg-slate-50">
                    <tr>
                      {[
                        "Bucket",
                        "Submitted",
                        "Approved",
                        "Rejected",
                        "Completed",
                      ].map((label) => (
                        <th
                          key={label}
                          className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-slate-600"
                        >
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {recentBuckets.length === 0 ? (
                      <tr>
                        <td className="px-3 py-4 text-slate-500" colSpan={5}>
                          No trend buckets recorded yet.
                        </td>
                      </tr>
                    ) : (
                      recentBuckets.map((bucket) => (
                        <tr key={`${bucket.start}-${bucket.end}`}>
                          <td className="px-3 py-3 text-slate-700">
                            {formatTimestamp(bucket.start)}
                          </td>
                          <td className="px-3 py-3 text-slate-900">
                            {bucket.submitted_count}
                          </td>
                          <td className="px-3 py-3 text-slate-900">
                            {bucket.approved_count}
                          </td>
                          <td className="px-3 py-3 text-slate-900">
                            {bucket.rejected_count}
                          </td>
                          <td className="px-3 py-3 text-slate-900">
                            {bucket.completed_count}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Delivery and timing
              </h3>
              <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                <div>
                  <div className="font-medium text-slate-900">
                    Approval delivery
                  </div>
                  <div className="mt-1">
                    {summary.approval_delivery_sent_count} sent
                  </div>
                  <div>{summary.approval_delivery_pending_count} pending</div>
                  <div>{summary.approval_delivery_failed_count} failed</div>
                </div>
                <div>
                  <div className="font-medium text-slate-900">
                    Invite delivery
                  </div>
                  <div className="mt-1">
                    {summary.invite_queued_count} queued
                  </div>
                  <div>{summary.invite_sent_count} sent</div>
                  <div>{summary.invite_failed_count} failed</div>
                </div>
                <div>
                  <div className="font-medium text-slate-900">
                    Recent milestones
                  </div>
                  <div className="mt-1">
                    Submitted: {formatTimestamp(summary.latest_submitted_at)}
                  </div>
                  <div>
                    Approved: {formatTimestamp(summary.latest_approved_at)}
                  </div>
                  <div>
                    Rejected: {formatTimestamp(summary.latest_rejected_at)}
                  </div>
                  <div>
                    Completed: {formatTimestamp(summary.latest_completed_at)}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-slate-900">
                    Window uniqueness
                  </div>
                  <div className="mt-1">
                    {summary.unique_guests_window} guests
                  </div>
                  <div>{summary.unique_sponsors_window} sponsors</div>
                  <div>{summary.unique_companies_window} companies</div>
                  <div>
                    {summary.avg_approval_minutes} minute average to approval
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 overflow-x-auto rounded-md border border-slate-200 bg-white shadow-sm">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50">
                <tr>
                  {[
                    "Guest",
                    "Contact",
                    "Sponsor",
                    "Status",
                    "Delivery",
                    "Timestamps",
                    "Actions",
                  ].map((label) => (
                    <th
                      key={label}
                      className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-600"
                    >
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {loading ? (
                  <tr>
                    <td className="px-5 py-6 text-slate-500" colSpan={7}>
                      Loading...
                    </td>
                  </tr>
                ) : records.length === 0 ? (
                  <tr>
                    <td className="px-5 py-6 text-slate-500" colSpan={7}>
                      No guest registrations found.
                    </td>
                  </tr>
                ) : (
                  records.map((record) => (
                    <tr key={record.id}>
                      <td className="px-5 py-4">
                        <div className="font-semibold text-slate-900">
                          {record.full_name || "Unnamed guest"}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {record.company || "No company"}
                          {record.role ? ` / ${record.role}` : ""}
                        </div>
                        {record.purpose ? (
                          <div className="mt-1 text-xs text-slate-500">
                            {record.purpose}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        <div>{record.email || "No email"}</div>
                        <div className="mt-1 text-xs text-slate-500">
                          {record.phone || "No phone"}
                        </div>
                        {record.client_mac || record.client_ip ? (
                          <div className="mt-1 text-xs text-slate-500">
                            {record.client_mac || "No MAC"} /{" "}
                            {record.client_ip || "No IP"}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        <div>{record.sponsor_name || "No sponsor name"}</div>
                        <div className="mt-1 text-xs text-slate-500">
                          {record.sponsor_email ||
                            record.sponsor_phone ||
                            "No sponsor contact"}
                        </div>
                        {record.approved_by ? (
                          <div className="mt-1 text-xs text-slate-500">
                            Handled by {record.approved_by}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${statusPillClass(record.status || "unknown")}`}
                        >
                          {record.status || "unknown"}
                        </span>
                        {record.rejection_reason ? (
                          <div className="mt-2 text-xs text-red-700">
                            {record.rejection_reason}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        <div>
                          Approval: {record.approval_delivery_status || "n/a"}
                        </div>
                        <div className="mt-1">
                          Invite: {record.invite_delivery_status || "n/a"}
                        </div>
                        {record.approval_delivery_error ||
                        record.invite_delivery_error ? (
                          <div className="mt-2 text-xs text-red-700">
                            {record.approval_delivery_error ||
                              record.invite_delivery_error}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4 text-xs text-slate-600">
                        <div>
                          <span className="font-medium text-slate-900">
                            Created:
                          </span>{" "}
                          {formatTimestamp(record.created_at)}
                        </div>
                        {record.approved_at ? (
                          <div className="mt-1">
                            <span className="font-medium text-slate-900">
                              Approved:
                            </span>{" "}
                            {formatTimestamp(record.approved_at)}
                          </div>
                        ) : null}
                        {record.rejected_at ? (
                          <div className="mt-1">
                            <span className="font-medium text-slate-900">
                              Rejected:
                            </span>{" "}
                            {formatTimestamp(record.rejected_at)}
                          </div>
                        ) : null}
                        {record.completed_at ? (
                          <div className="mt-1">
                            <span className="font-medium text-slate-900">
                              Completed:
                            </span>{" "}
                            {formatTimestamp(record.completed_at)}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        {record.status === "pending" ? (
                          <div className="flex flex-wrap gap-2">
                            <button
                              type="button"
                              onClick={() => approve(record.id)}
                              disabled={busyAction === `approve-${record.id}`}
                              className="rounded-md bg-sky-700 px-3 py-1.5 text-white hover:bg-sky-800 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              onClick={() => reject(record.id)}
                              disabled={busyAction === `reject-${record.id}`}
                              className="rounded-md bg-red-700 px-3 py-1.5 text-white hover:bg-red-800 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              Reject
                            </button>
                          </div>
                        ) : (
                          <span className="text-slate-500">No action</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
