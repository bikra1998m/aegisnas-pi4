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

type GuestDeliveryAnalyticsBucket = {
  start: string;
  end: string;
  submitted_count: number;
  pending_sponsor_approval_count: number;
  approval_delivery_failed_count: number;
  approved_count: number;
  rejected_count: number;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  completed_count: number;
};

type GuestDeliveryAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  sponsor_approval_required_count: number;
  pending_sponsor_approval_count: number;
  pending_invite_queue_count: number;
  approval_delivery_pending_count: number;
  approval_delivery_sent_count: number;
  approval_delivery_failed_count: number;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  approved_count: number;
  rejected_count: number;
  completed_count: number;
  unique_guests_window: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_approval_minutes: number;
  max_approval_minutes: number;
  avg_approval_to_completion_minutes: number;
  max_approval_to_completion_minutes: number;
  latest_submitted_at?: string;
  latest_approved_at?: string;
  latest_rejected_at?: string;
  latest_completed_at?: string;
  sponsors: GuestLifecycleCount[];
  companies: GuestLifecycleCount[];
  roles: GuestLifecycleCount[];
  approval_delivery_statuses: GuestLifecycleCount[];
  invite_delivery_statuses: GuestLifecycleCount[];
  buckets: GuestDeliveryAnalyticsBucket[];
};

type GuestDeliveryAnalyticsReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestDeliveryAnalyticsSummary;
};

type GuestInviteAnalyticsBucket = {
  start: string;
  end: string;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  completed_after_invite_count: number;
};

type GuestInviteAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  tracked_invite_records_count: number;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  invite_not_requested_count: number;
  completed_after_invite_count: number;
  unique_guests_window: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_approval_to_invite_minutes: number;
  max_approval_to_invite_minutes: number;
  avg_invite_to_completion_minutes: number;
  max_invite_to_completion_minutes: number;
  latest_invite_queued_at?: string;
  latest_invite_sent_at?: string;
  latest_invite_failed_at?: string;
  latest_invite_completed_at?: string;
  sponsors: GuestLifecycleCount[];
  companies: GuestLifecycleCount[];
  roles: GuestLifecycleCount[];
  invite_delivery_statuses: GuestLifecycleCount[];
  invite_failure_reasons: GuestLifecycleCount[];
  buckets: GuestInviteAnalyticsBucket[];
};

type GuestInviteAnalyticsReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestInviteAnalyticsSummary;
};

type GuestConversionAnalyticsBucket = {
  start: string;
  end: string;
  submitted_count: number;
  approved_count: number;
  rejected_count: number;
  invite_sent_count: number;
  completed_count: number;
};

type GuestConversionAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  open_pending_count: number;
  sponsor_approval_required_count: number;
  approved_stage_count: number;
  rejected_stage_count: number;
  invite_queued_count: number;
  invite_sent_count: number;
  invite_failed_count: number;
  completed_stage_count: number;
  approved_without_successful_invite_count: number;
  invited_not_completed_count: number;
  completed_after_invite_count: number;
  unique_guests_window: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  approval_rate_percent: number;
  invite_send_rate_percent: number;
  invite_completion_rate_percent: number;
  end_to_end_completion_rate_percent: number;
  avg_submit_to_approval_minutes: number;
  max_submit_to_approval_minutes: number;
  avg_submit_to_invite_minutes: number;
  max_submit_to_invite_minutes: number;
  avg_submit_to_completion_minutes: number;
  max_submit_to_completion_minutes: number;
  latest_submitted_at?: string;
  latest_approved_at?: string;
  latest_invite_sent_at?: string;
  latest_completed_at?: string;
  roles: GuestLifecycleCount[];
  sponsors: GuestLifecycleCount[];
  companies: GuestLifecycleCount[];
  buckets: GuestConversionAnalyticsBucket[];
};

type GuestConversionAnalyticsReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestConversionAnalyticsSummary;
};

type GuestRejectionAnalyticsBucket = {
  start: string;
  end: string;
  rejected_count: number;
  rejected_with_sponsor_count: number;
  rejected_without_sponsor_count: number;
  rejected_after_approval_count: number;
};

type GuestRejectionAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  rejected_count: number;
  rejected_with_sponsor_count: number;
  rejected_without_sponsor_count: number;
  rejected_after_approval_count: number;
  rejected_before_approval_count: number;
  unique_rejection_reasons_window: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_submit_to_rejection_minutes: number;
  max_submit_to_rejection_minutes: number;
  latest_rejected_at?: string;
  rejection_reasons: GuestLifecycleCount[];
  sponsors: GuestLifecycleCount[];
  companies: GuestLifecycleCount[];
  roles: GuestLifecycleCount[];
  buckets: GuestRejectionAnalyticsBucket[];
};

type GuestRejectionAnalyticsReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestRejectionAnalyticsSummary;
};

type GuestDeliveryFailureCounterparty = {
  name: string;
  delivery_issue_records_count: number;
  approval_delivery_failed_count: number;
  invite_failed_count: number;
  pending_invite_queue_count: number;
  total_failure_count: number;
  avg_pending_invite_queue_minutes: number;
  max_pending_invite_queue_minutes: number;
  latest_issue_at?: string;
};

type GuestDeliveryFailureBucket = {
  start: string;
  end: string;
  approval_delivery_failed_count: number;
  invite_failed_count: number;
  pending_invite_queue_count: number;
  total_failure_count: number;
};

type GuestDeliveryFailureSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  delivery_issue_records_count: number;
  approval_delivery_failed_count: number;
  invite_failed_count: number;
  pending_invite_queue_count: number;
  total_failure_count: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_pending_invite_queue_minutes: number;
  max_pending_invite_queue_minutes: number;
  latest_approval_failure_at?: string;
  latest_invite_failure_at?: string;
  latest_queued_invite_at?: string;
  approval_errors: GuestLifecycleCount[];
  invite_errors: GuestLifecycleCount[];
  sponsors: GuestDeliveryFailureCounterparty[];
  companies: GuestDeliveryFailureCounterparty[];
  buckets: GuestDeliveryFailureBucket[];
};

type GuestDeliveryFailureReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestDeliveryFailureSummary;
};

type GuestSponsorAnalyticsSponsor = {
  name: string;
  pending_count: number;
  approved_count: number;
  rejected_count: number;
  completed_count: number;
  older_than_30_minutes_count: number;
  older_than_4_hours_count: number;
  older_than_24_hours_count: number;
  avg_approval_minutes: number;
  max_approval_minutes: number;
  latest_submitted_at?: string;
  latest_approved_at?: string;
};

type GuestSponsorAnalyticsBucket = {
  start: string;
  end: string;
  submitted_count: number;
  pending_sponsor_approval_count: number;
  pending_older_than_30_minutes_count: number;
  pending_older_than_4_hours_count: number;
  pending_older_than_24_hours_count: number;
  approved_count: number;
  rejected_count: number;
  completed_count: number;
};

type GuestSponsorAnalyticsSummary = {
  window_hours: number;
  bucket_count: number;
  bucket_minutes: number;
  total_records: number;
  sponsor_approval_required_count: number;
  pending_sponsor_approval_count: number;
  pending_older_than_30_minutes_count: number;
  pending_older_than_4_hours_count: number;
  pending_older_than_24_hours_count: number;
  approved_with_sponsor_count: number;
  rejected_with_sponsor_count: number;
  completed_with_sponsor_count: number;
  unique_sponsors_window: number;
  unique_companies_window: number;
  avg_approval_minutes: number;
  max_approval_minutes: number;
  avg_pending_approval_minutes: number;
  max_pending_approval_minutes: number;
  latest_submitted_at?: string;
  latest_approved_at?: string;
  latest_rejected_at?: string;
  sponsors: GuestSponsorAnalyticsSponsor[];
  companies: GuestLifecycleCount[];
  buckets: GuestSponsorAnalyticsBucket[];
};

type GuestSponsorAnalyticsReport = {
  generated_at: string;
  status?: string;
  window_hours: number;
  bucket_count: number;
  summary: GuestSponsorAnalyticsSummary;
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

function MixList({
  title,
  items,
  empty,
}: {
  title: string;
  items: GuestLifecycleCount[];
  empty: string;
}) {
  return (
    <div>
      <div className="text-sm font-medium text-slate-900">{title}</div>
      {items.length === 0 ? (
        <div className="mt-2 text-sm text-slate-500">{empty}</div>
      ) : (
        <div className="mt-2 space-y-2">
          {items.slice(0, 5).map((item) => (
            <div
              key={`${title}-${item.name}`}
              className="flex items-center justify-between gap-3 text-sm text-slate-700"
            >
              <span className="truncate">{item.name}</span>
              <span className="font-medium text-slate-900">{item.count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function GuestRegistrations() {
  const [report, setReport] = useState<GuestLifecycleReport | null>(null);
  const [deliveryReport, setDeliveryReport] =
    useState<GuestDeliveryAnalyticsReport | null>(null);
  const [inviteReport, setInviteReport] =
    useState<GuestInviteAnalyticsReport | null>(null);
  const [conversionReport, setConversionReport] =
    useState<GuestConversionAnalyticsReport | null>(null);
  const [rejectionReport, setRejectionReport] =
    useState<GuestRejectionAnalyticsReport | null>(null);
  const [failureReport, setFailureReport] =
    useState<GuestDeliveryFailureReport | null>(null);
  const [sponsorReport, setSponsorReport] =
    useState<GuestSponsorAnalyticsReport | null>(null);
  const [selectedStatus, setSelectedStatus] = useState("");
  const [loadingLifecycle, setLoadingLifecycle] = useState(true);
  const [loadingDelivery, setLoadingDelivery] = useState(true);
  const [loadingInvite, setLoadingInvite] = useState(true);
  const [loadingConversion, setLoadingConversion] = useState(true);
  const [loadingRejection, setLoadingRejection] = useState(true);
  const [loadingFailures, setLoadingFailures] = useState(true);
  const [loadingSponsor, setLoadingSponsor] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busyAction, setBusyAction] = useState("");

  const buildQuerySuffix = () => {
    const params = new URLSearchParams();
    if (selectedStatus) {
      params.set("status", selectedStatus);
    }
    params.set("limit", "200");
    return params.toString() ? `?${params.toString()}` : "";
  };

  const fetchLifecycleReport = async (showMessage = false) => {
    try {
      const suffix = buildQuerySuffix();
      const lifecycleResponse = await api.get<GuestLifecycleReport>(
        `/system/guest-lifecycle${suffix}`,
      );
      setReport(lifecycleResponse.data);
      if (showMessage) {
        setMessage("Guest reports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest lifecycle report.",
      );
    } finally {
      setLoadingLifecycle(false);
    }
  };

  const fetchDeliveryReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const deliveryResponse = await api.get<GuestDeliveryAnalyticsReport>(
        `/system/guest-delivery-analytics${suffix}`,
      );
      setDeliveryReport(deliveryResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest delivery analytics.",
      );
    } finally {
      setLoadingDelivery(false);
    }
  };

  const fetchInviteReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const inviteResponse = await api.get<GuestInviteAnalyticsReport>(
        `/system/guest-invite-analytics${suffix}`,
      );
      setInviteReport(inviteResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest invite analytics.",
      );
    } finally {
      setLoadingInvite(false);
    }
  };

  const fetchConversionReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const conversionResponse = await api.get<GuestConversionAnalyticsReport>(
        `/system/guest-conversion-analytics${suffix}`,
      );
      setConversionReport(conversionResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest conversion analytics.",
      );
    } finally {
      setLoadingConversion(false);
    }
  };

  const fetchSponsorReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const sponsorResponse = await api.get<GuestSponsorAnalyticsReport>(
        `/system/guest-sponsor-analytics${suffix}`,
      );
      setSponsorReport(sponsorResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest sponsor analytics.",
      );
    } finally {
      setLoadingSponsor(false);
    }
  };

  const fetchRejectionReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const rejectionResponse = await api.get<GuestRejectionAnalyticsReport>(
        `/system/guest-rejection-analytics${suffix}`,
      );
      setRejectionReport(rejectionResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest rejection analytics.",
      );
    } finally {
      setLoadingRejection(false);
    }
  };

  const fetchFailureReport = async () => {
    try {
      const suffix = buildQuerySuffix();
      const failureResponse = await api.get<GuestDeliveryFailureReport>(
        `/system/guest-delivery-failures${suffix}`,
      );
      setFailureReport(failureResponse.data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load guest delivery failure analytics.",
      );
    } finally {
      setLoadingFailures(false);
    }
  };

  const fetchReports = async (showMessage = false) => {
    setError("");
    setLoadingLifecycle(true);
    setLoadingDelivery(true);
    setLoadingInvite(true);
    setLoadingConversion(true);
    setLoadingRejection(true);
    setLoadingFailures(true);
    setLoadingSponsor(true);
    await Promise.allSettled([
      fetchLifecycleReport(showMessage),
      fetchDeliveryReport(),
      fetchInviteReport(),
      fetchConversionReport(),
      fetchRejectionReport(),
      fetchFailureReport(),
      fetchSponsorReport(),
    ]);
  };

  useEffect(() => {
    void fetchReports();
    const interval = window.setInterval(() => {
      void fetchReports();
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
      await Promise.allSettled([
        fetchLifecycleReport(),
        fetchDeliveryReport(),
        fetchInviteReport(),
        fetchConversionReport(),
        fetchRejectionReport(),
        fetchFailureReport(),
        fetchSponsorReport(),
      ]);
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
      await Promise.allSettled([
        fetchLifecycleReport(),
        fetchDeliveryReport(),
        fetchInviteReport(),
        fetchConversionReport(),
        fetchRejectionReport(),
        fetchFailureReport(),
        fetchSponsorReport(),
      ]);
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not reject guest request.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadExport = async (
    reportKind:
      | "lifecycle"
      | "delivery"
      | "rejection"
      | "invite"
      | "conversion"
      | "failures"
      | "sponsor",
    format: "json" | "csv",
  ) => {
    setBusyAction(`export-${reportKind}-${format}`);
    try {
      const params = new URLSearchParams({ format });
      if (selectedStatus) {
        params.set("status", selectedStatus);
      }
      const endpoint =
        reportKind === "lifecycle"
          ? "/system/guest-lifecycle/export"
          : reportKind === "delivery"
            ? "/system/guest-delivery-analytics/export"
            : reportKind === "rejection"
              ? "/system/guest-rejection-analytics/export"
            : reportKind === "invite"
              ? "/system/guest-invite-analytics/export"
              : reportKind === "conversion"
                ? "/system/guest-conversion-analytics/export"
              : reportKind === "failures"
                ? "/system/guest-delivery-failures/export"
                : "/system/guest-sponsor-analytics/export";
      const response = await api.get(`${endpoint}?${params.toString()}`, {
        responseType: "blob",
      });
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
        filenameMatch?.[1] ||
        `aegisnas-guest-${
          reportKind === "lifecycle"
            ? "lifecycle"
            : reportKind === "delivery"
              ? "delivery-analytics"
              : reportKind === "rejection"
                ? "rejection-analytics"
              : reportKind === "invite"
                ? "invite-analytics"
                : reportKind === "conversion"
                  ? "conversion-analytics"
                : reportKind === "failures"
                  ? "delivery-failures"
                  : "sponsor-analytics"
        }.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      setMessage(
        `Guest ${
          reportKind === "lifecycle"
            ? "lifecycle"
            : reportKind === "delivery"
              ? "delivery analytics"
              : reportKind === "rejection"
                ? "rejection analytics"
              : reportKind === "invite"
                ? "invite analytics"
                : reportKind === "conversion"
                  ? "conversion analytics"
                : reportKind === "failures"
                  ? "delivery failures"
                  : "sponsor analytics"
        } ${format.toUpperCase()} export downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export guest workflow report.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const records = report?.history || [];
  const summary = report?.summary;
  const deliverySummary = deliveryReport?.summary;
  const inviteSummary = inviteReport?.summary;
  const conversionSummary = conversionReport?.summary;
  const rejectionSummary = rejectionReport?.summary;
  const failureSummary = failureReport?.summary;
  const sponsorSummary = sponsorReport?.summary;
  const recentBuckets = useMemo(
    () => (summary?.buckets || []).slice(-6),
    [summary],
  );
  const recentDeliveryBuckets = useMemo(
    () => (deliverySummary?.buckets || []).slice(-6),
    [deliverySummary],
  );
  const recentInviteBuckets = useMemo(
    () => (inviteSummary?.buckets || []).slice(-6),
    [inviteSummary],
  );
  const recentConversionBuckets = useMemo(
    () => (conversionSummary?.buckets || []).slice(-6),
    [conversionSummary],
  );
  const recentRejectionBuckets = useMemo(
    () => (rejectionSummary?.buckets || []).slice(-6),
    [rejectionSummary],
  );
  const recentFailureBuckets = useMemo(
    () => (failureSummary?.buckets || []).slice(-6),
    [failureSummary],
  );
  const recentSponsorBuckets = useMemo(
    () => (sponsorSummary?.buckets || []).slice(-6),
    [sponsorSummary],
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
            onClick={() => void fetchReports(true)}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("lifecycle", "json")}
            disabled={busyAction === "export-lifecycle-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Lifecycle JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("lifecycle", "csv")}
            disabled={busyAction === "export-lifecycle-csv"}
            className="rounded-md bg-sky-700 px-3 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Lifecycle CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("delivery", "json")}
            disabled={busyAction === "export-delivery-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Delivery JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("delivery", "csv")}
            disabled={busyAction === "export-delivery-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Delivery CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("rejection", "json")}
            disabled={busyAction === "export-rejection-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Rejection JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("rejection", "csv")}
            disabled={busyAction === "export-rejection-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Rejection CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("invite", "json")}
            disabled={busyAction === "export-invite-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Invite JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("invite", "csv")}
            disabled={busyAction === "export-invite-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Invite CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("conversion", "json")}
            disabled={busyAction === "export-conversion-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Conversion JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("conversion", "csv")}
            disabled={busyAction === "export-conversion-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Conversion CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("failures", "json")}
            disabled={busyAction === "export-failures-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Failures JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("failures", "csv")}
            disabled={busyAction === "export-failures-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Failures CSV
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("sponsor", "json")}
            disabled={busyAction === "export-sponsor-json"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Sponsor JSON
          </button>
          <button
            type="button"
            onClick={() => void downloadExport("sponsor", "csv")}
            disabled={busyAction === "export-sponsor-csv"}
            className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:border-slate-400 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Sponsor CSV
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
          {loadingLifecycle
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
              {!deliverySummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingDelivery
                    ? "Loading guest delivery analytics..."
                    : "Guest delivery analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                  <div>
                    <div className="font-medium text-slate-900">
                      Sponsor backlog
                    </div>
                    <div className="mt-1">
                      {deliverySummary.pending_sponsor_approval_count} waiting
                      for sponsor action
                    </div>
                    <div>
                      {deliverySummary.approval_delivery_pending_count} delivery
                      attempts pending
                    </div>
                    <div>
                      {deliverySummary.approval_delivery_failed_count} delivery
                      failures
                    </div>
                  </div>
                  <div>
                    <div className="font-medium text-slate-900">
                      Invite delivery
                    </div>
                    <div className="mt-1">
                      {deliverySummary.pending_invite_queue_count} still queued
                    </div>
                    <div>{deliverySummary.invite_sent_count} sent</div>
                    <div>{deliverySummary.invite_failed_count} failed</div>
                  </div>
                  <div>
                    <div className="font-medium text-slate-900">
                      Recent milestones
                    </div>
                    <div className="mt-1">
                      Submitted:{" "}
                      {formatTimestamp(deliverySummary.latest_submitted_at)}
                    </div>
                    <div>
                      Approved:{" "}
                      {formatTimestamp(deliverySummary.latest_approved_at)}
                    </div>
                    <div>
                      Rejected:{" "}
                      {formatTimestamp(deliverySummary.latest_rejected_at)}
                    </div>
                    <div>
                      Completed:{" "}
                      {formatTimestamp(deliverySummary.latest_completed_at)}
                    </div>
                  </div>
                  <div>
                    <div className="font-medium text-slate-900">
                      Timing window
                    </div>
                    <div className="mt-1">
                      {deliverySummary.avg_approval_minutes} minute average to
                      approval
                    </div>
                    <div>
                      {deliverySummary.max_approval_minutes} minute slowest
                      approval
                    </div>
                    <div>
                      {deliverySummary.avg_approval_to_completion_minutes}{" "}
                      minute average from approval to completion
                    </div>
                    <div>
                      {deliverySummary.max_approval_to_completion_minutes}{" "}
                      minute slowest approval-to-completion
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Conversion funnel
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Submission, approval, invite, and completion movement across the
                current guest window.
              </p>
              {!conversionSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingConversion
                    ? "Loading guest conversion analytics..."
                    : "Guest conversion analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Submitted",
                          "Approved",
                          "Rejected",
                          "Invited",
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
                      {recentConversionBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={6}>
                            No conversion buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentConversionBuckets.map((bucket) => (
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
                              {bucket.invite_sent_count}
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
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Conversion highlights
              </h3>
              {!conversionSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingConversion
                    ? "Loading guest conversion analytics..."
                    : "Guest conversion analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Funnel coverage
                      </div>
                      <div className="mt-1">
                        {conversionSummary.total_records} submitted
                      </div>
                      <div>
                        {conversionSummary.approved_stage_count} reached
                        approval
                      </div>
                      <div>
                        {conversionSummary.invite_sent_count} received invites
                      </div>
                      <div>
                        {conversionSummary.completed_stage_count} completed
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Drop-off points
                      </div>
                      <div className="mt-1">
                        {conversionSummary.open_pending_count} still pending
                      </div>
                      <div>
                        {
                          conversionSummary
                            .approved_without_successful_invite_count
                        }{" "}
                        approved without a successful invite
                      </div>
                      <div>
                        {conversionSummary.invited_not_completed_count} invited
                        but not completed
                      </div>
                      <div>
                        {conversionSummary.rejected_stage_count} rejected
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Conversion rates
                      </div>
                      <div className="mt-1">
                        {conversionSummary.approval_rate_percent}% approval
                        reach
                      </div>
                      <div>
                        {conversionSummary.invite_send_rate_percent}% invite
                        send rate
                      </div>
                      <div>
                        {conversionSummary.invite_completion_rate_percent}%
                        invite completion rate
                      </div>
                      <div>
                        {conversionSummary.end_to_end_completion_rate_percent}%
                        end-to-end completion
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Timing window
                      </div>
                      <div className="mt-1">
                        {conversionSummary.avg_submit_to_approval_minutes}
                        m average submit-to-approval
                      </div>
                      <div>
                        {conversionSummary.avg_submit_to_invite_minutes}m
                        average submit-to-invite
                      </div>
                      <div>
                        {conversionSummary.avg_submit_to_completion_minutes}m
                        average submit-to-completion
                      </div>
                      <div>
                        Latest completion:{" "}
                        {formatTimestamp(
                          conversionSummary.latest_completed_at,
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-3">
                    <MixList
                      title="Roles"
                      items={conversionSummary.roles}
                      empty="No role conversion activity recorded yet."
                    />
                    <MixList
                      title="Sponsors"
                      items={conversionSummary.sponsors}
                      empty="No sponsor conversion activity recorded yet."
                    />
                    <MixList
                      title="Companies"
                      items={conversionSummary.companies}
                      empty="No company conversion activity recorded yet."
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Sponsor delivery analytics
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Recent request flow for sponsor approvals and invite delivery.
              </p>
              {!deliverySummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingDelivery
                    ? "Loading guest delivery analytics..."
                    : "Guest delivery analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Submitted",
                          "Waiting sponsor",
                          "Approval failed",
                          "Approved",
                          "Invite sent",
                          "Invite failed",
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
                      {recentDeliveryBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={8}>
                            No delivery buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentDeliveryBuckets.map((bucket) => (
                          <tr key={`${bucket.start}-${bucket.end}`}>
                            <td className="px-3 py-3 text-slate-700">
                              {formatTimestamp(bucket.start)}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.submitted_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_sponsor_approval_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.approval_delivery_failed_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.approved_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_sent_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_failed_count}
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
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Workflow mix
              </h3>
              {!deliverySummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingDelivery
                    ? "Loading guest delivery analytics..."
                    : "Guest delivery analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <MixList
                      title="Sponsors"
                      items={deliverySummary.sponsors}
                      empty="No sponsor activity recorded yet."
                    />
                    <MixList
                      title="Companies"
                      items={deliverySummary.companies}
                      empty="No company activity recorded yet."
                    />
                    <MixList
                      title="Approval delivery states"
                      items={deliverySummary.approval_delivery_statuses}
                      empty="No approval delivery states recorded yet."
                    />
                    <MixList
                      title="Invite delivery states"
                      items={deliverySummary.invite_delivery_statuses}
                      empty="No invite delivery states recorded yet."
                    />
                  </div>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Unique activity
                      </div>
                      <div className="mt-1">
                        {deliverySummary.unique_guests_window} guests
                      </div>
                      <div>
                        {deliverySummary.unique_sponsors_window} sponsors
                      </div>
                      <div>
                        {deliverySummary.unique_companies_window} companies
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">Role mix</div>
                      {deliverySummary.roles.slice(0, 3).map((item) => (
                        <div key={`role-${item.name}`} className="mt-1">
                          {item.name}: {item.count}
                        </div>
                      ))}
                      {deliverySummary.roles.length === 0 ? (
                        <div className="mt-1 text-slate-500">
                          No role mix recorded yet.
                        </div>
                      ) : null}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Invite throughput and completion
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Recent invite queue, send, failure, and post-invite completion
                movement.
              </p>
              {!inviteSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingInvite
                    ? "Loading guest invite analytics..."
                    : "Guest invite analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Queued",
                          "Sent",
                          "Failed",
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
                      {recentInviteBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={5}>
                            No invite buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentInviteBuckets.map((bucket) => (
                          <tr key={`${bucket.start}-${bucket.end}`}>
                            <td className="px-3 py-3 text-slate-700">
                              {formatTimestamp(bucket.start)}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_queued_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_sent_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_failed_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.completed_after_invite_count}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Invite delivery highlights
              </h3>
              {!inviteSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingInvite
                    ? "Loading guest invite analytics..."
                    : "Guest invite analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Invite throughput
                      </div>
                      <div className="mt-1">
                        {inviteSummary.tracked_invite_records_count} tracked
                        invite records
                      </div>
                      <div>{inviteSummary.invite_queued_count} queued</div>
                      <div>{inviteSummary.invite_sent_count} sent</div>
                      <div>{inviteSummary.invite_failed_count} failed</div>
                      <div>
                        {inviteSummary.completed_after_invite_count} completed
                        after invite
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Timing window
                      </div>
                      <div className="mt-1">
                        {inviteSummary.avg_approval_to_invite_minutes} minute
                        average approval-to-invite
                      </div>
                      <div>
                        {inviteSummary.max_approval_to_invite_minutes} minute
                        slowest approval-to-invite
                      </div>
                      <div>
                        {inviteSummary.avg_invite_to_completion_minutes} minute
                        average invite-to-completion
                      </div>
                      <div>
                        {inviteSummary.max_invite_to_completion_minutes} minute
                        slowest invite-to-completion
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Latest milestones
                      </div>
                      <div className="mt-1">
                        Queued:{" "}
                        {formatTimestamp(inviteSummary.latest_invite_queued_at)}
                      </div>
                      <div>
                        Sent:{" "}
                        {formatTimestamp(inviteSummary.latest_invite_sent_at)}
                      </div>
                      <div>
                        Failed:{" "}
                        {formatTimestamp(inviteSummary.latest_invite_failed_at)}
                      </div>
                      <div>
                        Completed:{" "}
                        {formatTimestamp(
                          inviteSummary.latest_invite_completed_at,
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">Coverage</div>
                      <div className="mt-1">
                        {inviteSummary.unique_guests_window} guests
                      </div>
                      <div>{inviteSummary.unique_sponsors_window} sponsors</div>
                      <div>
                        {inviteSummary.unique_companies_window} companies
                      </div>
                      <div>
                        {inviteSummary.invite_not_requested_count} without
                        invite requests
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <MixList
                      title="Invite delivery states"
                      items={inviteSummary.invite_delivery_statuses}
                      empty="No invite delivery states recorded yet."
                    />
                    <MixList
                      title="Invite failure reasons"
                      items={inviteSummary.invite_failure_reasons}
                      empty="No invite failures recorded yet."
                    />
                    <MixList
                      title="Sponsors"
                      items={inviteSummary.sponsors}
                      empty="No sponsor invite activity recorded yet."
                    />
                    <MixList
                      title="Companies"
                      items={inviteSummary.companies}
                      empty="No company invite activity recorded yet."
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Sponsor approval backlog
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Aging pending approvals and recent sponsor-response movement.
              </p>
              {!sponsorSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingSponsor
                    ? "Loading guest sponsor analytics..."
                    : "Guest sponsor analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Submitted",
                          "Waiting sponsor",
                          ">30m",
                          ">4h",
                          ">24h",
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
                      {recentSponsorBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={9}>
                            No sponsor-approval buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentSponsorBuckets.map((bucket) => (
                          <tr key={`${bucket.start}-${bucket.end}`}>
                            <td className="px-3 py-3 text-slate-700">
                              {formatTimestamp(bucket.start)}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.submitted_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_sponsor_approval_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_older_than_30_minutes_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_older_than_4_hours_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_older_than_24_hours_count}
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
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Sponsor approval highlights
              </h3>
              {!sponsorSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingSponsor
                    ? "Loading guest sponsor analytics..."
                    : "Guest sponsor analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Backlog aging
                      </div>
                      <div className="mt-1">
                        {sponsorSummary.pending_sponsor_approval_count} waiting
                        for sponsor action
                      </div>
                      <div>
                        {sponsorSummary.pending_older_than_30_minutes_count}{" "}
                        older than 30 minutes
                      </div>
                      <div>
                        {sponsorSummary.pending_older_than_4_hours_count} older
                        than 4 hours
                      </div>
                      <div>
                        {sponsorSummary.pending_older_than_24_hours_count} older
                        than 24 hours
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Timing window
                      </div>
                      <div className="mt-1">
                        {sponsorSummary.avg_approval_minutes} minute average to
                        approval
                      </div>
                      <div>
                        {sponsorSummary.max_approval_minutes} minute slowest
                        approval
                      </div>
                      <div>
                        {sponsorSummary.avg_pending_approval_minutes} minute
                        average waiting time
                      </div>
                      <div>
                        {sponsorSummary.max_pending_approval_minutes} minute
                        oldest pending request
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Latest milestones
                      </div>
                      <div className="mt-1">
                        Submitted:{" "}
                        {formatTimestamp(sponsorSummary.latest_submitted_at)}
                      </div>
                      <div>
                        Approved:{" "}
                        {formatTimestamp(sponsorSummary.latest_approved_at)}
                      </div>
                      <div>
                        Rejected:{" "}
                        {formatTimestamp(sponsorSummary.latest_rejected_at)}
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">Coverage</div>
                      <div className="mt-1">
                        {sponsorSummary.sponsor_approval_required_count} sponsor
                        approvals required
                      </div>
                      <div>
                        {sponsorSummary.approved_with_sponsor_count} approved
                      </div>
                      <div>
                        {sponsorSummary.rejected_with_sponsor_count} rejected
                      </div>
                      <div>
                        {sponsorSummary.completed_with_sponsor_count} completed
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        Top sponsor queues
                      </div>
                      {sponsorSummary.sponsors.length === 0 ? (
                        <div className="mt-2 text-sm text-slate-500">
                          No sponsor queues recorded yet.
                        </div>
                      ) : (
                        <div className="mt-2 space-y-3">
                          {sponsorSummary.sponsors
                            .slice(0, 4)
                            .map((sponsor) => (
                              <div
                                key={sponsor.name}
                                className="rounded-md border border-slate-200 px-3 py-3"
                              >
                                <div className="text-sm font-medium text-slate-900">
                                  {sponsor.name}
                                </div>
                                <div className="mt-1 text-xs text-slate-600">
                                  {sponsor.pending_count} pending,{" "}
                                  {sponsor.older_than_4_hours_count} older than
                                  4h, {sponsor.older_than_24_hours_count} older
                                  than 24h
                                </div>
                                <div className="mt-1 text-xs text-slate-600">
                                  Avg approval {sponsor.avg_approval_minutes}m,
                                  slowest {sponsor.max_approval_minutes}m
                                </div>
                              </div>
                            ))}
                        </div>
                      )}
                    </div>
                    <MixList
                      title="Companies"
                      items={sponsorSummary.companies}
                      empty="No sponsor-company activity recorded yet."
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Rejection patterns
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Recent rejection movement, sponsor involvement, and post-approval
                reversals across the selected window.
              </p>
              {!rejectionSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingRejection
                    ? "Loading guest rejection analytics..."
                    : "Guest rejection analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Rejected",
                          "With sponsor",
                          "Without sponsor",
                          "After approval",
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
                      {recentRejectionBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={5}>
                            No rejection buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentRejectionBuckets.map((bucket) => (
                          <tr key={`${bucket.start}-${bucket.end}`}>
                            <td className="px-3 py-3 text-slate-700">
                              {formatTimestamp(bucket.start)}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.rejected_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.rejected_with_sponsor_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.rejected_without_sponsor_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.rejected_after_approval_count}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Rejection highlights
              </h3>
              {!rejectionSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingRejection
                    ? "Loading guest rejection analytics..."
                    : "Guest rejection analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Rejection mix
                      </div>
                      <div className="mt-1">
                        {rejectionSummary.rejected_count} total rejections
                      </div>
                      <div>
                        {rejectionSummary.rejected_with_sponsor_count} with
                        sponsor involvement
                      </div>
                      <div>
                        {rejectionSummary.rejected_without_sponsor_count} without
                        sponsor involvement
                      </div>
                      <div>
                        {rejectionSummary.rejected_after_approval_count} after
                        approval
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Timing window
                      </div>
                      <div className="mt-1">
                        {rejectionSummary.avg_submit_to_rejection_minutes} minute
                        average submit-to-rejection
                      </div>
                      <div>
                        {rejectionSummary.max_submit_to_rejection_minutes} minute
                        slowest submit-to-rejection
                      </div>
                      <div>
                        {rejectionSummary.unique_rejection_reasons_window} unique
                        rejection reasons
                      </div>
                      <div>
                        Latest rejection:{" "}
                        {formatTimestamp(rejectionSummary.latest_rejected_at)}
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">Coverage</div>
                      <div className="mt-1">
                        {rejectionSummary.unique_sponsors_window} sponsors
                      </div>
                      <div>
                        {rejectionSummary.unique_companies_window} companies
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Stage split
                      </div>
                      <div className="mt-1">
                        {rejectionSummary.rejected_before_approval_count} before
                        approval
                      </div>
                      <div>
                        {rejectionSummary.rejected_after_approval_count} after
                        approval
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <MixList
                      title="Rejection reasons"
                      items={rejectionSummary.rejection_reasons}
                      empty="No rejection reasons recorded yet."
                    />
                    <MixList
                      title="Roles"
                      items={rejectionSummary.roles}
                      empty="No rejected role mix recorded yet."
                    />
                    <MixList
                      title="Sponsors"
                      items={rejectionSummary.sponsors}
                      empty="No sponsor rejection activity recorded yet."
                    />
                    <MixList
                      title="Companies"
                      items={rejectionSummary.companies}
                      empty="No company rejection activity recorded yet."
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Delivery failure hotspots
              </h3>
              <p className="mt-1 text-sm text-slate-600">
                Recent approval or invite failures and queue pressure across the
                selected window.
              </p>
              {!failureSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingFailures
                    ? "Loading guest delivery failure analytics..."
                    : "Guest delivery failure analytics are not available yet."}
                </div>
              ) : (
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        {[
                          "Bucket",
                          "Approval failed",
                          "Invite failed",
                          "Queued",
                          "Total failures",
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
                      {recentFailureBuckets.length === 0 ? (
                        <tr>
                          <td className="px-3 py-4 text-slate-500" colSpan={5}>
                            No delivery-failure buckets recorded yet.
                          </td>
                        </tr>
                      ) : (
                        recentFailureBuckets.map((bucket) => (
                          <tr key={`${bucket.start}-${bucket.end}`}>
                            <td className="px-3 py-3 text-slate-700">
                              {formatTimestamp(bucket.start)}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.approval_delivery_failed_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.invite_failed_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.pending_invite_queue_count}
                            </td>
                            <td className="px-3 py-3 text-slate-900">
                              {bucket.total_failure_count}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-4 shadow-sm">
              <h3 className="text-base font-semibold text-slate-900">
                Failure reasons and queues
              </h3>
              {!failureSummary ? (
                <div className="mt-4 rounded-md border border-dashed border-slate-300 px-4 py-8 text-sm text-slate-500">
                  {loadingFailures
                    ? "Loading guest delivery failure analytics..."
                    : "Guest delivery failure analytics are not available yet."}
                </div>
              ) : (
                <>
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <MixList
                      title="Approval failure reasons"
                      items={failureSummary.approval_errors}
                      empty="No approval delivery failures recorded yet."
                    />
                    <MixList
                      title="Invite failure reasons"
                      items={failureSummary.invite_errors}
                      empty="No invite delivery failures recorded yet."
                    />
                  </div>
                  <div className="mt-4 grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                    <div>
                      <div className="font-medium text-slate-900">
                        Queue pressure
                      </div>
                      <div className="mt-1">
                        {failureSummary.pending_invite_queue_count} invites are
                        still queued
                      </div>
                      <div>
                        {failureSummary.avg_pending_invite_queue_minutes} minute
                        average queue age
                      </div>
                      <div>
                        {failureSummary.max_pending_invite_queue_minutes} minute
                        oldest queued invite
                      </div>
                    </div>
                    <div>
                      <div className="font-medium text-slate-900">
                        Latest issue anchors
                      </div>
                      <div className="mt-1">
                        Approval failure:{" "}
                        {formatTimestamp(
                          failureSummary.latest_approval_failure_at,
                        )}
                      </div>
                      <div>
                        Invite failure:{" "}
                        {formatTimestamp(
                          failureSummary.latest_invite_failure_at,
                        )}
                      </div>
                      <div>
                        Invite queued:{" "}
                        {formatTimestamp(
                          failureSummary.latest_queued_invite_at,
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        Top sponsor hotspots
                      </div>
                      {failureSummary.sponsors.length === 0 ? (
                        <div className="mt-2 text-sm text-slate-500">
                          No sponsor delivery hotspots recorded yet.
                        </div>
                      ) : (
                        <div className="mt-2 space-y-3">
                          {failureSummary.sponsors.slice(0, 3).map((item) => (
                            <div
                              key={item.name}
                              className="rounded-md border border-slate-200 px-3 py-3"
                            >
                              <div className="text-sm font-medium text-slate-900">
                                {item.name}
                              </div>
                              <div className="mt-1 text-xs text-slate-600">
                                {item.total_failure_count} failures,{" "}
                                {item.pending_invite_queue_count} queued invites
                              </div>
                              <div className="mt-1 text-xs text-slate-600">
                                Avg queue{" "}
                                {item.avg_pending_invite_queue_minutes}
                                m, oldest{" "}
                                {item.max_pending_invite_queue_minutes}m
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        Top company hotspots
                      </div>
                      {failureSummary.companies.length === 0 ? (
                        <div className="mt-2 text-sm text-slate-500">
                          No company delivery hotspots recorded yet.
                        </div>
                      ) : (
                        <div className="mt-2 space-y-3">
                          {failureSummary.companies.slice(0, 3).map((item) => (
                            <div
                              key={item.name}
                              className="rounded-md border border-slate-200 px-3 py-3"
                            >
                              <div className="text-sm font-medium text-slate-900">
                                {item.name}
                              </div>
                              <div className="mt-1 text-xs text-slate-600">
                                {item.total_failure_count} failures,{" "}
                                {item.delivery_issue_records_count} affected
                                records
                              </div>
                              <div className="mt-1 text-xs text-slate-600">
                                Invite failed {item.invite_failed_count}, queue{" "}
                                {item.pending_invite_queue_count}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
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
                {loadingLifecycle ? (
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
