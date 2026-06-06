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
  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [analyticsError, setAnalyticsError] = useState("");
  const [analyticsMessage, setAnalyticsMessage] = useState("");
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

  useEffect(() => {
    void fetchAnalytics(false);
  }, [windowHours, bucketCount]);

  useEffect(() => {
    const handler = () => {
      void fetchAnalytics(false);
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
                onClick={() => void fetchAnalytics(true)}
                disabled={loadingAnalytics || busyAction !== ""}
                className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50"
              >
                {loadingAnalytics
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
