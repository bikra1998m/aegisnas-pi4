import { useEffect, useMemo, useState } from "react";
import CrudPage from "../components/CrudPage";
import api from "../api/client";

type VoucherAnalyticsCount = {
  name: string;
  count: number;
};

type VoucherAnalyticsBucket = {
  start: string;
  end: string;
  created_count: number;
  active_count: number;
  exhausted_count: number;
  expired_count: number;
  unused_count: number;
};

type VoucherAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_vouchers: number;
  created_in_window_count: number;
  active_count: number;
  exhausted_count: number;
  expired_count: number;
  expired_unused_count: number;
  unused_count: number;
  partially_used_count: number;
  fully_used_count: number;
  expiring_24_hours_count: number;
  expiring_7_days_count: number;
  total_issued_uses: number;
  total_used_uses: number;
  active_remaining_uses: number;
  utilization_percent: number;
  avg_duration_minutes: number;
  max_duration_minutes: number;
  latest_created_at?: string;
  roles: VoucherAnalyticsCount[];
  states: VoucherAnalyticsCount[];
  buckets: VoucherAnalyticsBucket[];
};

type VoucherAnalyticsPayload = {
  generated_at: string;
  window_hours: number;
  bucket_count: number;
  summary: VoucherAnalyticsSummary;
};

type VoucherRedemptionBucket = {
  start: string;
  end: string;
  session_start_count: number;
  unique_voucher_count: number;
  first_redeemed_count: number;
  ended_count: number;
  ended_traffic_total: number;
};

type VoucherRedemptionSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_vouchers: number;
  redeemed_voucher_count: number;
  never_redeemed_count: number;
  redeemed_in_window_count: number;
  first_redeemed_in_window_count: number;
  redeemed_once_count: number;
  redeemed_repeat_count: number;
  session_start_count: number;
  ended_session_count: number;
  active_session_count: number;
  active_voucher_count: number;
  redeemed_within_24_hours_count: number;
  redeemed_within_7_days_count: number;
  avg_sessions_per_redeemed_voucher: number;
  avg_first_redemption_delay_minutes: number;
  max_first_redemption_delay_minutes: number;
  ended_traffic_total: number;
  avg_ended_session_seconds: number;
  max_ended_session_seconds: number;
  latest_session_start_at?: string;
  roles: VoucherAnalyticsCount[];
  buckets: VoucherRedemptionBucket[];
};

type VoucherRedemptionPayload = {
  generated_at: string;
  window_hours: number;
  bucket_count: number;
  summary: VoucherRedemptionSummary;
};

function formatTimestamp(value?: string) {
  if (!value) {
    return "Not recorded";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function formatDurationMinutes(minutes: number) {
  if (!Number.isFinite(minutes) || minutes <= 0) {
    return "0m";
  }
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  if (hours > 0) {
    return `${hours}h ${remainder}m`;
  }
  return `${minutes}m`;
}

function formatSessionSeconds(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "0m";
  }
  return formatDurationMinutes(Math.round(seconds / 60));
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const fixed = value >= 10 || unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(fixed)} ${units[unitIndex]}`;
}

function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | number;
  hint: string;
}) {
  return (
    <div className="rounded-md border border-gray-200 px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-gray-900">{value}</div>
      <div className="mt-1 text-sm text-gray-600">{hint}</div>
    </div>
  );
}

function MixList({
  title,
  items,
  empty,
}: {
  title: string;
  items: VoucherAnalyticsCount[];
  empty: string;
}) {
  return (
    <section className="rounded-lg bg-white p-6 shadow">
      <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
      <div className="mt-4 space-y-2">
        {items.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">
            {empty}
          </div>
        ) : (
          items.map((item) => (
            <div
              key={item.name}
              className="flex items-center justify-between rounded-md border border-gray-200 px-4 py-3 text-sm"
            >
              <span className="text-gray-700">{item.name}</span>
              <span className="font-semibold text-gray-900">{item.count}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

export default function Vouchers() {
  const [analytics, setAnalytics] = useState<VoucherAnalyticsSummary | null>(
    null,
  );
  const [redemption, setRedemption] =
    useState<VoucherRedemptionSummary | null>(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [loadingRedemption, setLoadingRedemption] = useState(true);
  const [analyticsError, setAnalyticsError] = useState("");
  const [analyticsMessage, setAnalyticsMessage] = useState("");
  const [redemptionError, setRedemptionError] = useState("");
  const [redemptionMessage, setRedemptionMessage] = useState("");
  const [busyAction, setBusyAction] = useState("");
  const [windowHours, setWindowHours] = useState(24 * 30);

  const bucketCount = useMemo(() => {
    if (windowHours <= 24) return 24;
    if (windowHours <= 24 * 7) return 14;
    return 30;
  }, [windowHours]);

  const fetchAnalytics = async (announce = false) => {
    if (announce) {
      setAnalyticsError("");
      setAnalyticsMessage("");
    }
    setLoadingAnalytics(true);
    try {
      const { data } = await api.get<VoucherAnalyticsPayload>(
        `/system/voucher-analytics?window_hours=${windowHours}&bucket_count=${bucketCount}`,
      );
      setAnalytics(data.summary || null);
      if (announce) {
        setAnalyticsMessage("Voucher analytics refreshed.");
      }
    } catch (err: any) {
      setAnalyticsError(
        err.response?.data ||
          err.message ||
          "Could not load voucher analytics.",
      );
    } finally {
      setLoadingAnalytics(false);
    }
  };

  const fetchRedemption = async (announce = false) => {
    if (announce) {
      setRedemptionError("");
      setRedemptionMessage("");
    }
    setLoadingRedemption(true);
    try {
      const { data } = await api.get<VoucherRedemptionPayload>(
        `/system/voucher-redemption-analytics?window_hours=${windowHours}&bucket_count=${bucketCount}`,
      );
      setRedemption(data.summary || null);
      if (announce) {
        setRedemptionMessage("Voucher redemption analytics refreshed.");
      }
    } catch (err: any) {
      setRedemptionError(
        err.response?.data ||
          err.message ||
          "Could not load voucher redemption analytics.",
      );
    } finally {
      setLoadingRedemption(false);
    }
  };

  const refreshAll = async (announce = false) => {
    await Promise.all([fetchAnalytics(announce), fetchRedemption(announce)]);
  };

  useEffect(() => {
    void refreshAll(false);
  }, [windowHours, bucketCount]);

  useEffect(() => {
    const handler = () => {
      void refreshAll(false);
    };
    window.addEventListener("config-applied", handler);
    return () => window.removeEventListener("config-applied", handler);
  }, [windowHours, bucketCount]);

  const exportAnalytics = async (format: "json" | "csv") => {
    setAnalyticsError("");
    setAnalyticsMessage("");
    setBusyAction(`export-${format}`);
    try {
      const response = await api.get(
        `/system/voucher-analytics/export?format=${format}&window_hours=${windowHours}&bucket_count=${bucketCount}`,
        {
          responseType: "blob",
        },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-voucher-analytics.json"
          : "aegisnas-voucher-analytics.csv";
      link.click();
      URL.revokeObjectURL(url);
      setAnalyticsMessage(
        `Voucher analytics exported as ${format.toUpperCase()}.`,
      );
    } catch (err: any) {
      setAnalyticsError(
        err.response?.data ||
          err.message ||
          "Could not export voucher analytics.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const exportRedemptionAnalytics = async (format: "json" | "csv") => {
    setRedemptionError("");
    setRedemptionMessage("");
    setBusyAction(`export-redemption-${format}`);
    try {
      const response = await api.get(
        `/system/voucher-redemption-analytics/export?format=${format}&window_hours=${windowHours}&bucket_count=${bucketCount}`,
        {
          responseType: "blob",
        },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-voucher-redemption-analytics.json"
          : "aegisnas-voucher-redemption-analytics.csv";
      link.click();
      URL.revokeObjectURL(url);
      setRedemptionMessage(
        `Voucher redemption analytics exported as ${format.toUpperCase()}.`,
      );
    } catch (err: any) {
      setRedemptionError(
        err.response?.data ||
          err.message ||
          "Could not export voucher redemption analytics.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const topContent = (
    <div className="space-y-6">
      <section className="rounded-lg bg-white p-6 shadow">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Voucher Inventory Summary
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Watch voucher usage, expiry pressure, and remaining capacity
              without scanning raw codes one by one.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <label className="text-sm text-gray-700">
              <span className="mb-1 block font-medium">Analytics Window</span>
              <select
                value={windowHours}
                onChange={(event) => setWindowHours(Number(event.target.value))}
                className="rounded-md border border-gray-300 px-3 py-2 text-sm"
              >
                <option value={24}>Last 24 hours</option>
                <option value={24 * 7}>Last 7 days</option>
                <option value={24 * 30}>Last 30 days</option>
              </select>
            </label>
            <div className="flex flex-wrap gap-3 self-end">
              <button
                onClick={() => void refreshAll(true)}
                disabled={loadingAnalytics || loadingRedemption || busyAction !== ""}
                className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50"
              >
                {loadingAnalytics || loadingRedemption
                  ? "Refreshing Analytics..."
                  : "Refresh Analytics"}
              </button>
              <button
                onClick={() => void exportAnalytics("json")}
                disabled={busyAction !== ""}
                className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50"
              >
                Export Analytics JSON
              </button>
              <button
                onClick={() => void exportAnalytics("csv")}
                disabled={busyAction !== ""}
                className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50"
              >
                Export Analytics CSV
              </button>
            </div>
          </div>
        </div>

        {analyticsMessage && (
          <div className="mt-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
            {analyticsMessage}
          </div>
        )}
        {analyticsError && (
          <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {String(analyticsError)}
          </div>
        )}

        {loadingAnalytics ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading voucher analytics...
          </div>
        ) : !analytics ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No voucher analytics available yet.
          </div>
        ) : (
          <>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Total Vouchers"
                value={analytics.total_vouchers}
                hint="All vouchers currently stored on the appliance."
              />
              <StatCard
                label="Active"
                value={analytics.active_count}
                hint="Still usable and not exhausted or expired."
              />
              <StatCard
                label="Utilization"
                value={`${analytics.utilization_percent}%`}
                hint="Issued uses already consumed across finite-use vouchers."
              />
              <StatCard
                label="Remaining Uses"
                value={analytics.active_remaining_uses}
                hint="Uses still available on currently active finite vouchers."
              />
              <StatCard
                label="Expiring Soon"
                value={analytics.expiring_24_hours_count}
                hint="Active vouchers expiring within the next 24 hours."
              />
              <StatCard
                label="Expired Unused"
                value={analytics.expired_unused_count}
                hint="Expired vouchers that were never consumed."
              />
              <StatCard
                label="Average Duration"
                value={formatDurationMinutes(analytics.avg_duration_minutes)}
                hint="Average voucher session duration allowance."
              />
              <StatCard
                label="Latest Created"
                value={formatTimestamp(analytics.latest_created_at)}
                hint="Newest voucher currently in the table."
              />
            </div>

            <div className="mt-6 grid gap-6 xl:grid-cols-2">
              <MixList
                title="Role Mix"
                items={analytics.roles}
                empty="No voucher role distribution is available yet."
              />
              <MixList
                title="Voucher State Mix"
                items={analytics.states}
                empty="No voucher state distribution is available yet."
              />
            </div>
          </>
        )}
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Voucher Redemption Summary
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              See which vouchers are getting redeemed, how quickly first use
              happens, and where reuse or inactivity is piling up.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void exportRedemptionAnalytics("json")}
              disabled={busyAction !== ""}
              className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50"
            >
              Export Redemption JSON
            </button>
            <button
              onClick={() => void exportRedemptionAnalytics("csv")}
              disabled={busyAction !== ""}
              className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50"
            >
              Export Redemption CSV
            </button>
          </div>
        </div>

        {redemptionMessage && (
          <div className="mt-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
            {redemptionMessage}
          </div>
        )}
        {redemptionError && (
          <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {String(redemptionError)}
          </div>
        )}

        {loadingRedemption ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading voucher redemption analytics...
          </div>
        ) : !redemption ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No voucher redemption analytics available yet.
          </div>
        ) : (
          <>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Redeemed Vouchers"
                value={redemption.redeemed_voucher_count}
                hint="Current vouchers with at least one recorded voucher session."
              />
              <StatCard
                label="Never Redeemed"
                value={redemption.never_redeemed_count}
                hint="Current vouchers that have never been used at all."
              />
              <StatCard
                label="Window Session Starts"
                value={redemption.session_start_count}
                hint="Voucher session starts observed in the selected window."
              />
              <StatCard
                label="Active Voucher Sessions"
                value={redemption.active_session_count}
                hint="Voucher-authenticated sessions still open right now."
              />
              <StatCard
                label="Average First Use Delay"
                value={formatDurationMinutes(
                  redemption.avg_first_redemption_delay_minutes,
                )}
                hint="Average time from voucher creation to its first redemption."
              />
              <StatCard
                label="Avg Sessions Per Voucher"
                value={redemption.avg_sessions_per_redeemed_voucher.toFixed(2)}
                hint="How often redeemed vouchers tend to be reused."
              />
              <StatCard
                label="Ended Traffic"
                value={formatBytes(redemption.ended_traffic_total)}
                hint="Traffic recorded on voucher sessions that ended in the window."
              />
              <StatCard
                label="Latest Session Start"
                value={formatTimestamp(redemption.latest_session_start_at)}
                hint="Newest voucher-authenticated session start we have recorded."
              />
            </div>

            <div className="mt-6 grid gap-6 xl:grid-cols-2">
              <MixList
                title="Redeemed Role Mix"
                items={redemption.roles}
                empty="No redeemed voucher role mix is available yet."
              />
              <div className="rounded-md border border-gray-200 px-4 py-4">
                <h3 className="text-lg font-semibold text-gray-900">
                  Redemption Timing
                </h3>
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <StatCard
                    label="First Redeemed In Window"
                    value={redemption.first_redeemed_in_window_count}
                    hint="Vouchers whose first-ever use landed inside the selected window."
                  />
                  <StatCard
                    label="Redeemed In 24h"
                    value={redemption.redeemed_within_24_hours_count}
                    hint="Vouchers first used within 24 hours of creation."
                  />
                  <StatCard
                    label="Redeemed In 7 Days"
                    value={redemption.redeemed_within_7_days_count}
                    hint="Vouchers first used within a week of creation."
                  />
                  <StatCard
                    label="Average Ended Session"
                    value={formatSessionSeconds(
                      redemption.avg_ended_session_seconds,
                    )}
                    hint="Average completed voucher session length in the selected window."
                  />
                </div>
              </div>
            </div>
          </>
        )}
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Voucher Redemption Trend
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Track voucher session starts, first-time redemptions, and completed
            voucher traffic over the selected window.
          </p>
        </div>

        {loadingRedemption ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading redemption trend buckets...
          </div>
        ) : !redemption || redemption.buckets.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No voucher redemption trend buckets available yet.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {[
                    "Bucket",
                    "Session Starts",
                    "Unique Vouchers",
                    "First Redeemed",
                    "Ended",
                    "Ended Traffic",
                  ].map((label) => (
                    <th
                      key={label}
                      className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600"
                    >
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {redemption.buckets.map((bucket) => (
                  <tr key={`${bucket.start}-${bucket.end}`}>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      <div className="font-medium text-gray-900">
                        {formatTimestamp(bucket.start)}
                      </div>
                      <div className="text-xs text-gray-500">
                        to {formatTimestamp(bucket.end)}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.session_start_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.unique_voucher_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.first_redeemed_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.ended_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {formatBytes(bucket.ended_traffic_total)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Voucher Creation And State Trend
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Bucketed voucher creation counts and current-state mix over the
            selected window. Each bucket spans about{" "}
            {analytics?.bucket_minutes ||
              Math.round((windowHours * 60) / bucketCount)}{" "}
            minutes.
          </p>
        </div>

        {loadingAnalytics ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading trend buckets...
          </div>
        ) : !analytics || analytics.buckets.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No voucher trend buckets available yet.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-md border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {[
                    "Bucket",
                    "Created",
                    "Active",
                    "Exhausted",
                    "Expired",
                    "Unused",
                  ].map((label) => (
                    <th
                      key={label}
                      className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-600"
                    >
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {analytics.buckets.map((bucket) => (
                  <tr key={`${bucket.start}-${bucket.end}`}>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      <div className="font-medium text-gray-900">
                        {formatTimestamp(bucket.start)}
                      </div>
                      <div className="text-xs text-gray-500">
                        to {formatTimestamp(bucket.end)}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.created_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.active_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.exhausted_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.expired_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      {bucket.unused_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );

  return (
    <CrudPage
      title="Vouchers"
      endpoint="/vouchers"
      itemName="Voucher"
      topContent={topContent}
      columns={[
        { key: "code", label: "Code" },
        { key: "role", label: "Role" },
        { key: "duration_minutes", label: "Duration" },
        { key: "usage_limit", label: "Usage Limit" },
        { key: "used_count", label: "Used" },
        { key: "expires_at", label: "Expires At" },
      ]}
      fields={[
        { name: "code", label: "Code", required: true },
        {
          name: "role",
          label: "Role",
          required: true,
          defaultValue: "guest-basic",
        },
        {
          name: "duration_minutes",
          label: "Duration Minutes",
          type: "number",
          required: true,
          defaultValue: 1440,
        },
        {
          name: "usage_limit",
          label: "Usage Limit",
          type: "number",
          required: true,
          defaultValue: 1,
        },
        {
          name: "expires_at",
          label: "Expires At",
          placeholder: "2026-12-31T23:59:59Z",
        },
      ]}
    />
  );
}
