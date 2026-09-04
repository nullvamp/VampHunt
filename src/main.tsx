import React, { lazy, Suspense, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  ChevronLeft,
  ChevronRight,
  Database,
  Check,
  ExternalLink,
  Eye,
  FileText,
  FolderOpen,
  Play,
  Radar,
  Rows3,
  Search,
  SlidersHorizontal,
  Square,
  Trash2,
  X,
} from "lucide-react";
import "./styles.css";
const GraphView = lazy(() =>
  import("./GraphView").then((module) => ({ default: module.GraphView })),
);

type Capability = { id: string; name: string; artifacts: string[] };
type CaseSummary = {
  id: string;
  name: string;
  examiner: string;
  path: string;
  created_utc: string;
};
type Artifact = {
  path: string;
  kind: string;
  parser: string;
  size: number;
  confidence: string;
};
type Inventory = {
  files: number;
  bytes: number;
  detected: Record<string, number>;
  artifacts: Artifact[];
  truncated: boolean;
  unreadable: number;
};
type EvidenceImport = {
  path: string;
  files: number;
  bytes: number;
  manifest: string;
  reused: boolean;
};
type TimelineEvent = {
  id: number;
  timestamp_utc: string | null;
  artifact_type: string;
  event_type: string;
  host: string | null;
  user: string | null;
  path: string | null;
  process: string | null;
  summary: string;
  source_database: string;
  source_table: string;
  source_row_id: string;
};
type EventPage = {
  rows: TimelineEvent[];
  total: number;
  page: number;
  page_size: number;
};
type EventFilter = {
  search: string;
  artifact_type: string[];
  event_type: string[];
  host: string[];
  user: string[];
  from_utc: string;
  to_utc: string;
  page: number;
  page_size: number;
};
type EventFilterOptions = {
  artifact_types: string[];
  event_types: string[];
  hosts: string[];
  users: string[];
};
type Relationship = {
  source_type: string;
  source_value: string;
  target_type: string;
  target_value: string;
  relation: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
};
type Overview = { events: number; entities: number; relationships: number };
type Finding = {
  id: number;
  title: string;
  severity: string;
  status: string;
  notes: string;
  created_utc: string;
  updated_utc: string;
  evidence_count: number;
};
type SourceRecord = {
  event_id: number;
  database: string;
  table: string;
  row_reference: string;
  fields: Record<string, unknown>;
};
type ParserJob = {
  job_id: string;
  parser: string;
  status: string;
  phase: string;
  input: string;
  output: string | null;
  started_utc: string;
  updated_utc: string;
  completed_utc: string | null;
  normalized_events: number;
  message: string;
};
type ParserResult = {
  job_id: string;
  status: string;
  output: string;
  normalized: number;
};
type ArchiveResult = {
  path: string;
  files: number;
  bytes: number;
  sha256: string;
};
type DetectionStatus = {
  sigma_rules: number;
  sigma_compatible: number;
  hayabusa_rules: number;
  chainsaw_rules: number;
  correlation_rules: number;
  yara_rules: number;
  sigma_release: string;
  yara_release: string;
  hayabusa_release: string;
  chainsaw_release: string;
  yara_x_version: string;
  hayabusa_version: string;
  chainsaw_version: string;
  file_ready: boolean;
  event_ready: boolean;
  artifact_ready: boolean;
  ready: boolean;
};
type DetectionRunSummary = {
  yara_new_leads: number;
  hayabusa_new_leads: number;
  chainsaw_new_leads: number;
  correlation_new_leads: number;
  total_new_leads: number;
  files_considered: number;
  evtx_files: number;
  layers_run: string[];
};
type DetectionLead = {
  id: number;
  engine: string;
  rule_id: string;
  title: string;
  severity: string;
  target: string;
  source: string;
  created_utc: string;
  raw: string;
  supporting_events: number;
};

type GeneratedReport = {
  name: string;
  path: string;
  kind: string;
  bytes: number;
  modified_utc: string;
};

type PipelineView =
  | "case"
  | "evidence"
  | "jobs"
  | "connections"
  | "report";

type ReportTab = "findings" | "build" | "generated";
const reportSeverityOptions = ["Critical", "High", "Medium", "Low"];

const humanSize = (bytes: number) =>
  bytes < 1024
    ? `${bytes} Bytes`
    : bytes < 1048576
      ? `${(bytes / 1024).toFixed(1)} KB`
      : bytes < 1073741824
        ? `${(bytes / 1048576).toFixed(1)} MB`
        : `${(bytes / 1073741824).toFixed(2)} GB`;

const displayUtc = (value: string) => {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : `${parsed.toLocaleString(undefined, { timeZone: "UTC" })} UTC`;
};

const readablePath = (value: string) =>
  value.replaceAll("\\\\?\\UNC\\", "\\\\").replaceAll("\\\\?\\", "");

function VampHuntLogo({ size = 24 }: { size?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 40 40"
      focusable="false"
    >
      <g
        fill="none"
        stroke="#8B84F7"
        strokeWidth="5.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M24 6 L10.5 19.5 L12.4 21.4" />
        <path d="M17.2 31.2 L28.2 20.2" />
      </g>
      <rect x="18.2" y="17.9" width="3.8" height="3.8" rx="0.5" fill="#8B84F7" />
    </svg>
  );
}

function PathField({
  value,
  onChange,
  placeholder,
  browseTitle,
  directory = true,
  extensions,
  autoFocus = false,
  ariaLabel,
  disabled = false,
  onError,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  browseTitle: string;
  directory?: boolean;
  extensions?: string[];
  autoFocus?: boolean;
  ariaLabel?: string;
  disabled?: boolean;
  onError?: (message: string) => void;
}) {
  const browse = async () => {
    try {
      const selected = await openDialog({
        title: browseTitle,
        directory,
        multiple: false,
        defaultPath: value.trim() || undefined,
        filters:
          !directory && extensions
            ? [{ name: browseTitle, extensions }]
            : undefined,
      });
      if (typeof selected === "string") onChange(selected);
    } catch (error) {
      onError?.(String(error));
    }
  };

  return (
    <div className="path-field">
      <input
        autoFocus={autoFocus}
        value={readablePath(value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        onChange={(event) => onChange(event.target.value)}
      />
      <button
        type="button"
        className="path-browse"
        disabled={disabled}
        onClick={() => void browse()}
      >
        <FolderOpen size={14} />
        Browse
      </button>
    </div>
  );
}

const desktopWindow = getCurrentWindow();

function WindowTitleBar() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let unlisten: () => void = () => {};
    const syncMaximized = () =>
      desktopWindow
        .isMaximized()
        .then(setMaximized)
        .catch(() => undefined);

    void syncMaximized();
    desktopWindow
      .onResized(syncMaximized)
      .then((stopListening) => {
        unlisten = stopListening;
      })
      .catch(() => undefined);
    return () => unlisten();
  }, []);

  const toggleMaximize = async () => {
    await desktopWindow.toggleMaximize();
    setMaximized(await desktopWindow.isMaximized());
  };

  return (
    <div
      className="window-titlebar"
      data-tauri-drag-region
      onDoubleClick={(event) => {
        if ((event.target as HTMLElement).closest("button")) return;
        void toggleMaximize();
      }}
    >
      <div className="window-drag-surface" data-tauri-drag-region />
      <div className="window-controls">
        <button
          type="button"
          aria-label="Minimize"
          title="Minimize"
          onClick={() => void desktopWindow.minimize()}
        >
          <span className="window-icon window-icon-minimize" />
        </button>
        <button
          type="button"
          aria-label={maximized ? "Restore" : "Maximize"}
          title={maximized ? "Restore" : "Maximize"}
          onClick={() => void toggleMaximize()}
        >
          <span
            className={`window-icon ${maximized ? "window-icon-restore" : "window-icon-maximize"}`}
          />
        </button>
        <button
          type="button"
          className="window-close"
          aria-label="Close"
          title="Close"
          onClick={() => void desktopWindow.close()}
        >
          <X size={14} strokeWidth={1.5} />
        </button>
      </div>
    </div>
  );
}

function MultiFilter({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: string[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  const toggle = (value: string) =>
    onChange(
      selected.includes(value)
        ? selected.filter((item) => item !== value)
        : [...selected, value],
    );
  return (
    <div className="multi-filter" ref={root}>
      <button
        type="button"
        className={selected.length ? "has-selection" : ""}
        onClick={() => setOpen((value) => !value)}
      >
        <span>{selected.length ? `${selected.length} selected` : label}</span>
        <b>⌄</b>
      </button>
      {open && (
        <div className="multi-menu">
          <header>
            <strong>{label}</strong>
            {selected.length > 0 && (
              <button type="button" onClick={() => onChange([])}>
                Clear
              </button>
            )}
          </header>
          <div>
            {options.length === 0 ? (
              <p>No values found</p>
            ) : (
              options.map((value) => (
                <label key={value}>
                  <input
                    type="checkbox"
                    checked={selected.includes(value)}
                    onChange={() => toggle(value)}
                  />
                  <span title={value}>{value}</span>
                </label>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [activeCase, setActiveCase] = useState<CaseSummary | null>(null);
  const [casesRoot, setCasesRoot] = useState("C:\\DFIR\\Cases");
  const [caseName, setCaseName] = useState("");
  const [examiner, setExaminer] = useState("");
  const [openPath, setOpenPath] = useState("");
  const [evidencePath, setEvidencePath] = useState("");
  const [parserPath, setParserPath] = useState(
    "C:\\DFIR\\Tools\\Vamparser\\vamparser.exe",
  );
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [message, setMessage] = useState("Create or open a case to begin.");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<
    | "case"
    | "evidence"
    | "jobs"
    | "detections"
    | "explorer"
    | "connections"
    | "report"
  >("case");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [selectedEvents, setSelectedEvents] = useState<number[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingTitle, setFindingTitle] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("Medium");
  const [findingNotes, setFindingNotes] = useState("");
  const [sourceRecord, setSourceRecord] = useState<SourceRecord | null>(null);
  const [jobs, setJobs] = useState<ParserJob[]>([]);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [backupDirectory, setBackupDirectory] = useState("C:\\DFIR\\Backups");
  const [importPath, setImportPath] = useState("");
  const [detectionStatus, setDetectionStatus] =
    useState<DetectionStatus | null>(null);
  const [detectionLeads, setDetectionLeads] = useState<DetectionLead[]>([]);
  const [recentCases, setRecentCases] = useState<CaseSummary[]>(() => {
    try {
      const saved = JSON.parse(
        localStorage.getItem("vamphunt:cases") || "[]",
      ) as CaseSummary[];
      return saved.map((item) => ({
        ...item,
        path: readablePath(item.path),
      }));
    } catch {
      return [];
    }
  });
  const [caseAction, setCaseAction] = useState<
    "none" | "create" | "open" | "import"
  >("none");
  const [caseToDelete, setCaseToDelete] = useState<CaseSummary | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const [reportTab, setReportTab] = useState<ReportTab>("findings");
  const [reportSeverities, setReportSeverities] = useState<string[]>(
    reportSeverityOptions,
  );
  const [includeReportFindings, setIncludeReportFindings] = useState(true);
  const [includeReportLeads, setIncludeReportLeads] = useState(true);
  const [generatedReports, setGeneratedReports] = useState<GeneratedReport[]>([]);
  const [reportToDelete, setReportToDelete] = useState<GeneratedReport | null>(null);
  const [reportDeleteError, setReportDeleteError] = useState("");
  const [eventPage, setEventPage] = useState<EventPage>({
    rows: [],
    total: 0,
    page: 0,
    page_size: 100,
  });
  const [eventFilter, setEventFilter] = useState<EventFilter>({
    search: "",
    artifact_type: [],
    event_type: [],
    host: [],
    user: [],
    from_utc: "",
    to_utc: "",
    page: 0,
    page_size: 100,
  });
  const [showFilters, setShowFilters] = useState(false);
  const [eventDensity, setEventDensity] = useState<"compact" | "comfortable">(
    "compact",
  );
  const [leadSearch, setLeadSearch] = useState("");
  const [leadSeverity, setLeadSeverity] = useState("All");
  const [filterOptions, setFilterOptions] = useState<EventFilterOptions>({
    artifact_types: [],
    event_types: [],
    hosts: [],
    users: [],
  });
  const [visibleColumns, setVisibleColumns] = useState<string[]>([
    "time",
    "type",
    "host",
    "user",
    "process",
    "path",
    "summary",
    "source",
  ]);
  useEffect(() => {
    invoke<Capability[]>("parser_capabilities")
      .then(setCapabilities)
      .catch(() => setCapabilities([]));
    invoke<string | null>("locate_vamparser")
      .then((path) => {
        if (path) setParserPath(path);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (recentCases.length === 0) return;
    let stopped = false;
    const savedCases = [...recentCases];
    Promise.all(
      savedCases.map(async (item) => {
        try {
          return await invoke<CaseSummary>("open_case", {
            casePath: item.path,
          });
        } catch {
          return null;
        }
      }),
    ).then((checkedCases) => {
      if (stopped) return;
      const checkedIds = new Set(savedCases.map((item) => item.id));
      const available = new Map(
        checkedCases
          .filter((item): item is CaseSummary => item !== null)
          .map((item) => [item.id, item]),
      );
      setRecentCases((current) => {
        const next = current.flatMap((item) => {
          if (!checkedIds.has(item.id)) return [item];
          const verified = available.get(item.id);
          return verified ? [{ ...verified, path: readablePath(verified.path) }] : [];
        });
        localStorage.setItem("vamphunt:cases", JSON.stringify(next));
        return next;
      });
    });
    return () => {
      stopped = true;
    };
    // Recent paths are checked once when the application starts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!activeCase) {
      setJobs([]);
      return;
    }
    let stopped = false;
    const refresh = () =>
      invoke<ParserJob[]>("list_parser_jobs", { casePath: activeCase.path })
        .then((records) => {
          if (!stopped) setJobs(records);
        })
        .catch(() => undefined);
    refresh();
    const timer = window.setInterval(refresh, activeJobId ? 500 : 3000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [activeCase, activeJobId]);

  useEffect(() => {
    setInventory(null);
    setEvents([]);
    setRelationships([]);
    setSelectedEvents([]);
    setSourceRecord(null);
    setFindings([]);
    setDetectionLeads([]);
    setGeneratedReports([]);
    setReportTab("findings");
    if (!activeCase) {
      setOverview(null);
      return;
    }

    let stopped = false;
    const casePath = activeCase.path;
    Promise.allSettled([
      invoke<Overview>("investigation_overview", { casePath }),
      invoke<Finding[]>("list_findings", { casePath }),
      invoke<DetectionLead[]>("list_detection_leads", { casePath }),
      invoke<GeneratedReport[]>("list_generated_reports", { casePath }),
    ]).then(([overviewResult, findingsResult, leadsResult, reportsResult]) => {
      if (stopped) return;
      setOverview(
        overviewResult.status === "fulfilled" ? overviewResult.value : null,
      );
      setFindings(
        findingsResult.status === "fulfilled" ? findingsResult.value : [],
      );
      setDetectionLeads(
        leadsResult.status === "fulfilled" ? leadsResult.value : [],
      );
      setGeneratedReports(
        reportsResult.status === "fulfilled" ? reportsResult.value : [],
      );
    });

    return () => {
      stopped = true;
    };
  }, [activeCase?.path]);

  async function loadInvestigation(target: "explorer" | "connections") {
    if (!activeCase) return;
    setView(target);
    setBusy(true);
    try {
      const summary = await invoke<Overview>("investigation_overview", {
        casePath: activeCase.path,
      });
      setOverview(summary);
      if (target === "explorer") {
        const page = await invoke<EventPage>("explore_events", {
          casePath: activeCase.path,
          filter: eventFilter,
        });
        setEventPage(page);
        setEvents(page.rows);
      } else
        setRelationships(
          await invoke<Relationship[]>("relationship_edges", {
            casePath: activeCase.path,
            limit: 500,
          }),
        );
    } catch (error) {
      if (target === "explorer") setEvents([]);
      else setRelationships([]);
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function refreshFindings() {
    if (!activeCase) return;
    try {
      setFindings(
        await invoke<Finding[]>("list_findings", { casePath: activeCase.path }),
      );
    } catch (error) {
      setFindings([]);
      setMessage(String(error));
    }
  }
  async function loadDetections() {
    if (!activeCase) return;
    setView("detections");
    try {
      const [status, leads] = await Promise.all([
        invoke<DetectionStatus>("detection_status"),
        invoke<DetectionLead[]>("list_detection_leads", {
          casePath: activeCase.path,
        }),
      ]);
      setDetectionStatus(status);
      setDetectionLeads(leads);
    } catch (error) {
      setMessage(String(error));
    }
  }
  async function runDetections() {
    if (!activeCase || !evidencePath.trim()) return;
    localStorage.setItem(
      `vamphunt:evidence:${activeCase.path}`,
      evidencePath.trim(),
    );
    setBusy(true);
    setMessage(
      "Analyzing case evidence with file, event, artifact, and correlation rules...",
    );
    try {
      const result = await invoke<DetectionRunSummary>("run_detection_scan", {
        casePath: activeCase.path,
        evidencePath,
      });
      setMessage(
        `Analysis completed: ${result.total_new_leads.toLocaleString()} new leads from ${result.files_considered.toLocaleString()} files and ${result.evtx_files.toLocaleString()} EVTX files.`,
      );
      await loadDetections();
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }
  async function createFinding() {
    if (!activeCase) return;
    try {
      await invoke<number>("create_finding", {
        casePath: activeCase.path,
        title: findingTitle,
        severity: findingSeverity,
        notes: findingNotes,
        eventIds: selectedEvents,
      });
      setFindingTitle("");
      setFindingNotes("");
      setSelectedEvents([]);
      await refreshFindings();
      setMessage("Finding created with supporting events.");
    } catch (error) {
      setMessage(String(error));
    }
  }
  async function generateReport() {
    if (!activeCase) return;
    setBusy(true);
    try {
      const excludedFindingIds = findings
        .filter(
          (item) =>
            !includeReportFindings || !reportSeverities.includes(item.severity),
        )
        .map((item) => item.id);
      const excludedLeadIds = detectionLeads
        .filter(
          (item) =>
            !includeReportLeads || !reportSeverities.includes(item.severity),
        )
        .map((item) => item.id);
      const path = await invoke<string>("generate_html_report", {
        casePath: activeCase.path,
        excludedFindingIds,
        excludedLeadIds,
      });
      await refreshGeneratedReports();
      setReportTab("generated");
      setMessage(`Report saved: ${path}`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }
  async function refreshGeneratedReports() {
    if (!activeCase) return;
    try {
      setGeneratedReports(
        await invoke<GeneratedReport[]>("list_generated_reports", {
          casePath: activeCase.path,
        }),
      );
    } catch (error) {
      setGeneratedReports([]);
      setMessage(String(error));
    }
  }
  async function loadReport(tab: ReportTab = reportTab) {
    if (!activeCase) return;
    setView("report");
    setReportTab(tab);
    try {
      const [allFindings, allLeads, allReports] = await Promise.all([
        invoke<Finding[]>("list_findings", { casePath: activeCase.path }),
        invoke<DetectionLead[]>("list_detection_leads", {
          casePath: activeCase.path,
        }),
        invoke<GeneratedReport[]>("list_generated_reports", {
          casePath: activeCase.path,
        }),
      ]);
      setFindings(allFindings);
      setDetectionLeads(allLeads);
      setGeneratedReports(allReports);
    } catch (error) {
      setMessage(String(error));
    }
  }
  function rememberCase(value: CaseSummary) {
    const normalized = { ...value, path: readablePath(value.path) };
    setRecentCases((current) => {
      const next = [
        normalized,
        ...current.filter((item) => item.id !== normalized.id),
      ].slice(0, 12);
      localStorage.setItem("vamphunt:cases", JSON.stringify(next));
      return next;
    });
  }
  function forgetRecentCase(value: CaseSummary) {
    setRecentCases((current) => {
      const next = current.filter((item) => item.id !== value.id);
      localStorage.setItem("vamphunt:cases", JSON.stringify(next));
      return next;
    });
    localStorage.removeItem(`vamphunt:evidence:${value.path}`);
  }
  function loadEvidencePath(value: CaseSummary) {
    const saved = localStorage.getItem(`vamphunt:evidence:${value.path}`);
    setEvidencePath(saved || `${value.path}\\EVIDENCE`);
  }
  async function exportTimeline() {
    if (!activeCase) return;
    setBusy(true);
    try {
      const path = await invoke<string>("export_timeline_csv", {
        casePath: activeCase.path,
      });
      await refreshGeneratedReports();
      setReportTab("generated");
      setMessage(`Timeline CSV saved: ${path}`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }
  async function openGeneratedReport(item: GeneratedReport) {
    if (!activeCase) return;
    try {
      await invoke("open_generated_report", {
        casePath: activeCase.path,
        reportPath: item.path,
      });
      setMessage(`Opened ${item.name}.`);
    } catch (error) {
      setMessage(String(error));
    }
  }
  async function revealGeneratedReport(item: GeneratedReport) {
    if (!activeCase) return;
    try {
      await invoke("reveal_generated_report", {
        casePath: activeCase.path,
        reportPath: item.path,
      });
      setMessage(`Showing ${item.name} in Explorer.`);
    } catch (error) {
      setMessage(String(error));
    }
  }
  function requestReportDeletion(item: GeneratedReport) {
    setReportDeleteError("");
    setReportToDelete(item);
  }
  function cancelReportDeletion() {
    if (busy) return;
    setReportDeleteError("");
    setReportToDelete(null);
  }
  async function deleteGeneratedReport() {
    if (!activeCase || !reportToDelete) return;
    const target = reportToDelete;
    setBusy(true);
    setReportDeleteError("");
    try {
      await invoke<string>("delete_generated_report", {
        casePath: activeCase.path,
        reportPath: target.path,
      });
      setGeneratedReports((current) =>
        current.filter((item) => item.path !== target.path),
      );
      setReportToDelete(null);
      setMessage(`Deleted ${target.name}.`);
    } catch (error) {
      setReportDeleteError(String(error));
    } finally {
      setBusy(false);
    }
  }
  function toggleReportSeverity(severity: string) {
    setReportSeverities((current) =>
      current.includes(severity)
        ? current.filter((item) => item !== severity)
        : reportSeverityOptions.filter(
            (item) => item === severity || current.includes(item),
          ),
    );
  }
  async function setFindingStatus(id: number, status: string) {
    if (!activeCase) return;
    try {
      await invoke("update_finding_status", {
        casePath: activeCase.path,
        id,
        status,
      });
      await refreshFindings();
      setMessage(`Finding marked ${status}.`);
    } catch (error) {
      setMessage(String(error));
    }
  }
  function toggleEvent(id: number) {
    setSelectedEvents((current) =>
      current.includes(id)
        ? current.filter((value) => value !== id)
        : [...current, id],
    );
  }
  async function inspectEvent(id: number) {
    if (!activeCase) return;
    try {
      setSourceRecord(
        await invoke<SourceRecord>("event_source_record", {
          casePath: activeCase.path,
          eventId: id,
        }),
      );
    } catch (error) {
      setMessage(String(error));
    }
  }

  async function refreshOverview(casePath: string) {
    try {
      setOverview(
        await invoke<Overview>("investigation_overview", { casePath }),
      );
    } catch {
      setOverview(null);
    }
  }

  async function createCase() {
    setBusy(true);
    try {
      const result = await invoke<CaseSummary>("create_case", {
        basePath: casesRoot,
        name: caseName,
        examiner,
      });
      setActiveCase(result);
      loadEvidencePath(result);
      rememberCase(result);
      setOpenPath(result.path);
      setCaseAction("none");
      await refreshOverview(result.path);
      setMessage(`Created ${result.id}`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function openCase() {
    setBusy(true);
    try {
      const result = await invoke<CaseSummary>("open_case", {
        casePath: openPath,
      });
      setActiveCase(result);
      loadEvidencePath(result);
      rememberCase(result);
      setCaseAction("none");
      await refreshOverview(result.path);
      setMessage(`Opened ${result.id}`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function discover() {
    if (!activeCase) return;
    setBusy(true);
    try {
      setMessage(
        "Copying evidence into the active case and recording SHA-256 values...",
      );
      const imported = await invoke<EvidenceImport>("import_evidence", {
        casePath: activeCase.path,
        sourcePath: evidencePath,
      });
      setEvidencePath(imported.path);
      const result = await invoke<Inventory>("inventory_evidence", {
        casePath: imported.path,
      });
      setInventory(result);
      localStorage.setItem(
        `vamphunt:evidence:${activeCase.path}`,
        imported.path,
      );
      setMessage(
        `${imported.reused ? "Using case evidence." : `Imported and hashed ${imported.files.toLocaleString()} files (${humanSize(imported.bytes)}).`} ${result.artifacts.length.toLocaleString()} supported artifacts found.${result.unreadable ? ` ${result.unreadable.toLocaleString()} files could not be read.` : ""}`,
      );
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function runParser(item: Artifact) {
    if (!activeCase) {
      setMessage("Create or open a case first.");
      return;
    }
    setBusy(true);
    setMessage(`Running ${item.parser}…`);
    try {
      const result = await executeParser(item);
      setMessage(
        result.status === "completed"
          ? `Completed and normalized: ${result.output}`
          : `Parser failed. Review the case audit record.`,
      );
      if (result.status === "completed")
        setOverview(
          await invoke<Overview>("investigation_overview", {
            casePath: activeCase.path,
          }),
        );
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function executeParser(item: Artifact) {
    if (!activeCase) throw new Error("Create or open a case first.");
    const jobId = crypto.randomUUID();
    setActiveJobId(jobId);
    try {
      return await invoke<ParserResult>("run_parser", {
        casePath: activeCase.path,
        evidencePath,
        inputPath: item.path,
        parserPath,
        parser: item.parser,
        jobId,
      });
    } finally {
      setActiveJobId((current) => (current === jobId ? null : current));
    }
  }
  async function openRecent(item: CaseSummary) {
    setBusy(true);
    try {
      const result = await invoke<CaseSummary>("open_case", {
        casePath: item.path,
      });
      setActiveCase(result);
      loadEvidencePath(result);
      rememberCase(result);
      setOpenPath(result.path);
      await refreshOverview(result.path);
      setMessage(`Opened ${result.id}`);
    } catch (error) {
      const reason = String(error);
      if (reason.includes("not a VampHunt case")) {
        forgetRecentCase(item);
        setMessage(`Removed unavailable ${item.name} from Recent cases.`);
      } else {
        setMessage(reason);
      }
    } finally {
      setBusy(false);
    }
  }

  function requestCaseDeletion(item: CaseSummary) {
    setDeleteError("");
    setCaseToDelete(item);
  }

  function cancelCaseDeletion() {
    if (busy) return;
    setDeleteError("");
    setCaseToDelete(null);
  }

  async function deleteCase() {
    if (!caseToDelete) return;
    const target = caseToDelete;
    setBusy(true);
    setDeleteError("");
    try {
      await invoke<CaseSummary>("delete_case", {
        casePath: target.path,
        expectedId: target.id,
      });
      forgetRecentCase(target);
      if (activeCase?.path === target.path) {
        setActiveCase(null);
        setInventory(null);
        setView("case");
      }
      setCaseToDelete(null);
      setMessage(`Deleted ${target.name}.`);
    } catch (error) {
      const reason = String(error);
      if (reason.includes("case folder no longer exists")) {
        forgetRecentCase(target);
        if (activeCase?.id === target.id) {
          setActiveCase(null);
          setInventory(null);
          setView("case");
        }
        setCaseToDelete(null);
        setMessage(`Removed missing ${target.name} from Recent cases.`);
      } else {
        setDeleteError(reason);
      }
    } finally {
      setBusy(false);
    }
  }
  async function applyEventFilter(next: EventFilter = eventFilter) {
    if (!activeCase) return;
    setView("explorer");
    setEventFilter(next);
    setBusy(true);
    try {
      const page = await invoke<EventPage>("explore_events", {
        casePath: activeCase.path,
        filter: next,
      });
      setEventPage(page);
      setEvents(page.rows);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }
  async function loadExplorer() {
    if (!activeCase) return;
    setView("explorer");
    try {
      setFilterOptions(
        await invoke<EventFilterOptions>("event_filter_options", {
          casePath: activeCase.path,
        }),
      );
      await applyEventFilter({ ...eventFilter, page: 0 });
    } catch (error) {
      setMessage(String(error));
    }
  }
  function toggleColumn(column: string) {
    setVisibleColumns((current) =>
      current.includes(column)
        ? current.filter((value) => value !== column)
        : [...current, column],
    );
  }

  async function backupCase() {
    if (!activeCase) return;
    setBusy(true);
    setMessage("Creating and verifying the case backup...");
    try {
      const result = await invoke<ArchiveResult>("export_case", {
        casePath: activeCase.path,
        destination: backupDirectory,
      });
      setMessage(
        `Backup saved: ${result.path} · ${result.files.toLocaleString()} files · ${humanSize(result.bytes)} · SHA-256 ${result.sha256}`,
      );
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function importCase() {
    setBusy(true);
    setMessage("Verifying and importing the case backup...");
    try {
      const result = await invoke<CaseSummary>("import_case", {
        archivePath: importPath,
        casesRoot,
      });
      setActiveCase(result);
      loadEvidencePath(result);
      rememberCase(result);
      setOpenPath(result.path);
      setCaseAction("none");
      await refreshOverview(result.path);
      setMessage(`Imported and opened ${result.id}`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function cancelActiveJob() {
    if (!activeCase || !activeJobId) return;
    try {
      await invoke("cancel_parser", {
        casePath: activeCase.path,
        jobId: activeJobId,
      });
      setMessage("Stopping the current parser job...");
    } catch (error) {
      setMessage(String(error));
    }
  }

  async function parseDiscovered() {
    if (!activeCase || !inventory) return;
    const directoryParsers = new Set([
      "evtx",
      "prefetch",
      "lnk",
      "jump-lists",
      "recycle-bin",
    ]);
    const tasks: Artifact[] = [];
    const seen = new Set<string>();
    for (const item of inventory.artifacts) {
      const input = directoryParsers.has(item.parser)
        ? evidencePath
        : item.path;
      const key = `${item.parser}|${input.toLowerCase()}`;
      if (!item.parser || seen.has(key)) continue;
      seen.add(key);
      tasks.push({ ...item, path: input });
    }
    if (!tasks.length) {
      setMessage("No supported artifacts are ready to parse.");
      return;
    }
    setBusy(true);
    let completed = 0;
    const failed: string[] = [];
    try {
      for (let index = 0; index < tasks.length; index += 1) {
        const task = tasks[index];
        setMessage(`Parsing ${index + 1} of ${tasks.length}: ${task.kind}`);
        try {
          const result = await executeParser(task);
          if (result.status === "completed") completed += 1;
          else if (result.status === "cancelled") break;
          else failed.push(task.kind);
        } catch {
          failed.push(task.kind);
        }
      }
      if (completed)
        setOverview(
          await invoke<Overview>("investigation_overview", {
            casePath: activeCase.path,
          }),
        );
      const suffix = failed.length
        ? ` ${failed.length} failed; review the audit records.`
        : "";
      setMessage(`${completed} parser jobs completed.${suffix}`);
    } finally {
      setBusy(false);
    }
  }

  const activeEventFilterCount =
    eventFilter.artifact_type.length +
    eventFilter.event_type.length +
    eventFilter.host.length +
    eventFilter.user.length +
    (eventFilter.from_utc ? 1 : 0) +
    (eventFilter.to_utc ? 1 : 0);

  const leadSeverityCounts = detectionLeads.reduce<Record<string, number>>(
    (counts, lead) => {
      const severity = lead.severity.toLowerCase();
      counts[severity] = (counts[severity] ?? 0) + 1;
      return counts;
    },
    {},
  );

  const visibleDetectionLeads = detectionLeads.filter((lead) => {
    const severityMatches =
      leadSeverity === "All" ||
      lead.severity.toLowerCase() === leadSeverity.toLowerCase();
    const query = leadSearch.trim().toLowerCase();
    const queryMatches =
      !query ||
      `${lead.title} ${lead.target} ${lead.engine} ${lead.rule_id} ${lead.source}`
        .toLowerCase()
        .includes(query);
    return severityMatches && queryMatches;
  });

  const reportCandidates = [
    ...(includeReportFindings ? findings : []),
    ...(includeReportLeads ? detectionLeads : []),
  ];
  const reportSeverityCounts = reportCandidates.reduce<Record<string, number>>(
    (counts, item) => {
      counts[item.severity] = (counts[item.severity] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const includedReportFindings = includeReportFindings
    ? findings.filter((item) => reportSeverities.includes(item.severity))
    : [];
  const includedReportLeads = includeReportLeads
    ? detectionLeads.filter((item) => reportSeverities.includes(item.severity))
    : [];
  const includedReportItems =
    includedReportFindings.length + includedReportLeads.length;
  const excludedReportItems =
    findings.length + detectionLeads.length - includedReportItems;

  const savedEvidencePath = activeCase
    ? localStorage.getItem(`vamphunt:evidence:${activeCase.path}`)
    : null;
  const hasEvidence = Boolean(
    activeCase &&
      ((inventory?.files ?? 0) > 0 ||
        jobs.length > 0 ||
        (overview?.events ?? 0) > 0 ||
        detectionLeads.length > 0 ||
        savedEvidencePath),
  );
  const hasParsedRecords = Boolean(
    activeCase &&
      ((overview?.events ?? 0) > 0 ||
        jobs.some(
          (job) => job.status === "completed" && job.normalized_events > 0,
        )),
  );
  const hasReviewMaterial = Boolean(
    hasParsedRecords || findings.length > 0 || detectionLeads.length > 0,
  );
  const pipelineViews: PipelineView[] = [
    "case",
    "evidence",
    "jobs",
    "connections",
    "report",
  ];
  const isPipelineView = pipelineViews.includes(view as PipelineView);
  const suggestedPipelineView: PipelineView = !activeCase
    ? "case"
    : !hasEvidence
      ? "evidence"
    : !hasParsedRecords
      ? "jobs"
      : "report";
  const currentPipelineView = isPipelineView
    ? (view as PipelineView)
    : suggestedPipelineView;
  const pipelineSteps: Array<{
    id: PipelineView;
    label: string;
    complete: boolean;
    available: boolean;
    unavailableReason?: string;
    open: () => void | Promise<void>;
  }> = [
    {
      id: "case",
      label: "Case",
      complete: Boolean(activeCase),
      available: true,
      open: () => setView("case"),
    },
    {
      id: "evidence",
      label: "Evidence",
      complete: hasEvidence,
      available: Boolean(activeCase),
      unavailableReason: "Open a case first",
      open: () => setView("evidence"),
    },
    {
      id: "jobs",
      label: "Parser jobs",
      complete: hasParsedRecords,
      available: Boolean(activeCase && hasEvidence),
      unavailableReason: "Add evidence first",
      open: () => setView("jobs"),
    },
    {
      id: "connections",
      label: "Connections",
      complete: Boolean((overview?.relationships ?? 0) > 0),
      available: hasParsedRecords,
      unavailableReason: "Parse evidence first",
      open: () => loadInvestigation("connections"),
    },
    {
      id: "report",
      label: "Report",
      complete: generatedReports.length > 0,
      available: Boolean(activeCase && hasReviewMaterial),
      unavailableReason: "No results to report yet",
      open: () => loadReport(),
    },
  ];

  return (
    <div className="app-frame">
      <WindowTitleBar />
      <main className="shell">
      <aside>
        <div className="brand">
          <div className="mark">
            <VampHuntLogo size={24} />
          </div>
          <div>
            <strong>VampHunt</strong>
            <span>Evidence into answers</span>
          </div>
        </div>
        <nav className="sidebar-nav" aria-label="Case navigation">
          <div className="nav-section-label">CASE FLOW</div>
          <ol className="case-stepper">
            {pipelineSteps.map((step) => {
              const current = currentPipelineView === step.id;
              const suggested = current && !isPipelineView;
              const state = current
                ? suggested
                  ? "suggested"
                  : "current"
                : step.complete
                  ? "complete"
                  : step.available
                    ? "available"
                    : "locked";
              const status = current
                ? suggested
                  ? "Next"
                  : "Current"
                : step.complete
                  ? "Done"
                  : !step.available
                    ? step.unavailableReason
                    : "";
              return (
                <li key={step.id} className={`step-${state}`}>
                  <button
                    disabled={!step.available}
                    title={!step.available ? step.unavailableReason : undefined}
                    aria-current={current && !suggested ? "step" : undefined}
                    onClick={() => void step.open()}
                  >
                    <span className="step-marker" aria-hidden="true">
                      {step.complete && !current ? <Check size={10} /> : null}
                    </span>
                    <span className="step-label">
                      <strong>{step.label}</strong>
                      {status ? <small>{status}</small> : null}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>

          <div className="nav-section-label tools-label">TOOLS</div>
          <div className="tool-links">
            <button
              disabled={!hasParsedRecords}
              title={
                !activeCase
                  ? "Open a case first"
                  : !hasParsedRecords
                    ? "Parse evidence before opening Event explorer"
                    : undefined
              }
              className={view === "explorer" ? "active" : ""}
              onClick={loadExplorer}
            >
              <Database size={16} />
              <span>
                <strong>Event explorer</strong>
                {!hasParsedRecords ? <small>Available after parsing</small> : null}
              </span>
            </button>
            <button
              disabled={!activeCase}
              title={!activeCase ? "Open a case first" : undefined}
              className={view === "detections" ? "active" : ""}
              onClick={loadDetections}
            >
              <Radar size={16} />
              <span>
                <strong>Rule matches</strong>
                <small>Scan or review leads</small>
              </span>
            </button>
          </div>
        </nav>
        <div className="parser-status">
          {capabilities.length > 0 ? <Check size={14} /> : <X size={14} />}
          <strong>
            {capabilities.length > 0
              ? "Vamparser ready"
              : "Vamparser unavailable"}
          </strong>
        </div>
      </aside>
      <section className="workspace">
        <header>
          <div>
            <small>INVESTIGATION</small>
            <h1>{activeCase ? activeCase.name : "Cases"}</h1>
            <p>
              {activeCase
                ? `${activeCase.id} · ${activeCase.examiner}`
                : "Create a case or continue where you stopped."}
            </p>
          </div>
          {activeCase ? (
            <button
              className="case-switch"
              onClick={() => {
                setActiveCase(null);
                setView("case");
              }}
            >
              Switch case
            </button>
          ) : (
            <span className="offline">LOCAL</span>
          )}
        </header>

        {!activeCase && (
          <section className="case-launcher">
            <div className="launcher-actions">
              <button onClick={() => setCaseAction("create")}>
                Create case
              </button>
              <button onClick={() => setCaseAction("open")}>
                Open case folder
              </button>
              <button onClick={() => setCaseAction("import")}>
                Import backup
              </button>
            </div>
            <section className="recent-cases">
              <small>RECENT CASES</small>
              {recentCases.length === 0 ? (
                <p>No recent cases on this computer.</p>
              ) : (
                recentCases.map((item) => (
                  <div className="recent-case-row" key={item.path}>
                    <button
                      className="recent-case-open"
                      disabled={busy}
                      onClick={() => openRecent(item)}
                    >
                      <span>
                        <strong>{item.name}</strong>
                        <small>
                          {item.id} · {item.examiner}
                        </small>
                      </span>
                      <code>{readablePath(item.path)}</code>
                    </button>
                    <button
                      type="button"
                      className="recent-case-delete"
                      disabled={busy}
                      aria-label={`Delete ${item.name}`}
                      onClick={() => requestCaseDeletion(item)}
                    >
                      <Trash2 size={14} />
                      Delete
                    </button>
                  </div>
                ))
              )}
            </section>
            {caseAction !== "none" && (
              <div className="case-dialog">
                <article className="case-picker">
                  <button
                    type="button"
                    className="dialog-close"
                    aria-label="Close"
                    title="Close"
                    onClick={() => setCaseAction("none")}
                  >
                    <X size={16} strokeWidth={1.5} />
                  </button>
                  {caseAction === "create" && (
                    <>
                      <label>CREATE CASE</label>
                      <input
                        autoFocus
                        placeholder="Case name"
                        value={caseName}
                        onChange={(e) => setCaseName(e.target.value)}
                      />
                      <input
                        placeholder="Examiner"
                        value={examiner}
                        onChange={(e) => setExaminer(e.target.value)}
                      />
                      <PathField
                        value={casesRoot}
                        onChange={setCasesRoot}
                        placeholder="Cases folder"
                        browseTitle="Choose cases folder"
                        disabled={busy}
                        onError={setMessage}
                      />
                      <button
                        disabled={busy || !caseName.trim() || !examiner.trim()}
                        onClick={createCase}
                      >
                        Create case
                      </button>
                    </>
                  )}
                  {caseAction === "open" && (
                    <>
                      <label>OPEN CASE FOLDER</label>
                      <PathField
                        autoFocus
                        placeholder="Folder containing case.json"
                        value={openPath}
                        onChange={setOpenPath}
                        browseTitle="Choose case folder"
                        disabled={busy}
                        onError={setMessage}
                      />
                      <button
                        disabled={busy || !openPath.trim()}
                        onClick={openCase}
                      >
                        Open case
                      </button>
                    </>
                  )}
                  {caseAction === "import" && (
                    <>
                      <label>IMPORT CASE BACKUP</label>
                      <PathField
                        autoFocus
                        placeholder="Path to .vhcase backup"
                        value={importPath}
                        onChange={setImportPath}
                        browseTitle="Choose case backup"
                        directory={false}
                        extensions={["vhcase"]}
                        disabled={busy}
                        onError={setMessage}
                      />
                      <PathField
                        value={casesRoot}
                        onChange={setCasesRoot}
                        placeholder="Cases folder"
                        browseTitle="Choose cases folder"
                        disabled={busy}
                        onError={setMessage}
                      />
                      <button
                        disabled={busy || !importPath.trim()}
                        onClick={importCase}
                      >
                        Verify and import
                      </button>
                    </>
                  )}
                </article>
              </div>
            )}
            {caseToDelete && (
              <div className="case-dialog">
                <article className="case-picker delete-case-dialog">
                  <button
                    type="button"
                    className="dialog-close"
                    aria-label="Close"
                    title="Close"
                    disabled={busy}
                    onClick={cancelCaseDeletion}
                  >
                    <X size={16} strokeWidth={1.5} />
                  </button>
                  <label>DELETE CASE</label>
                  <h2>{caseToDelete.name}</h2>
                  <p>
                    This permanently deletes the case folder and everything
                    inside it, including evidence, parser output, findings,
                    and reports.
                  </p>
                  <code className="delete-case-path">
                    {readablePath(caseToDelete.path)}
                  </code>
                  {deleteError && <p className="delete-case-error">{deleteError}</p>}
                  <div className="delete-case-actions">
                    <button
                      type="button"
                      className="delete-cancel"
                      disabled={busy}
                      onClick={cancelCaseDeletion}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="delete-confirm"
                      disabled={busy}
                      onClick={() => void deleteCase()}
                    >
                      <Trash2 size={15} />
                      {busy ? "Deleting…" : "Delete case"}
                    </button>
                  </div>
                </article>
              </div>
            )}
          </section>
        )}

        {activeCase && view === "case" && (
          <>
            <section className="results">
              <div className="result-summary">
                <div>
                  <small>CASE ID</small>
                  <strong className="text-stat">{activeCase.id}</strong>
                </div>
                <div>
                  <small>EXAMINER</small>
                  <strong className="text-stat">{activeCase.examiner}</strong>
                </div>
                <div>
                  <small>NORMALIZED EVENTS</small>
                  <strong>{overview?.events.toLocaleString() ?? "-"}</strong>
                </div>
                <div>
                  <small>ENTITIES</small>
                  <strong>{overview?.entities.toLocaleString() ?? "-"}</strong>
                </div>
              </div>
              <div className="case-location">{readablePath(activeCase.path)}</div>
            </section>
            <section className="case-picker backup-panel">
              <label>CASE BACKUP</label>
              <p>
                Creates one verified .vhcase file containing the case, evidence,
                parser output, findings, reports, and audit records.
              </p>
              <div>
                <PathField
                  value={backupDirectory}
                  onChange={setBackupDirectory}
                  placeholder="Existing backup directory"
                  browseTitle="Choose backup folder"
                  disabled={busy}
                  onError={setMessage}
                />
                <button disabled={busy} onClick={backupCase}>
                  Create backup
                </button>
              </div>
            </section>
          </>
        )}
        {activeCase && view === "evidence" && (
          <>
            <section className="case-picker">
              <label>COLLECTED EVIDENCE DIRECTORY</label>
              <div>
                <PathField
                  value={evidencePath}
                  placeholder="Folder containing collected artifacts"
                  onChange={setEvidencePath}
                  browseTitle="Choose collected evidence folder"
                  disabled={busy}
                  onError={setMessage}
                />
                <button disabled={busy} onClick={discover}>
                  Import and discover
                </button>
                {inventory && (
                  <button disabled={busy} onClick={parseDiscovered}>
                    Parse discovered
                  </button>
                )}
              </div>
              <label>VAMPARSER</label>
              <PathField
                value={parserPath}
                onChange={setParserPath}
                placeholder="Path to vamparser.exe"
                browseTitle="Choose Vamparser executable"
                directory={false}
                extensions={["exe"]}
                disabled={busy}
                onError={setMessage}
              />
              <p>{readablePath(message)}</p>
            </section>
            {inventory && (
              <section className="results">
                <div className="result-summary">
                  <div>
                    <small>FILES SCANNED</small>
                    <strong>{inventory.files.toLocaleString()}</strong>
                  </div>
                  <div>
                    <small>SOURCE SIZE</small>
                    <strong>{humanSize(inventory.bytes)}</strong>
                  </div>
                  <div>
                    <small>SUPPORTED</small>
                    <strong>
                      {inventory.artifacts.length.toLocaleString()}
                    </strong>
                  </div>
                  <div>
                    <small>ARTIFACT TYPES</small>
                    <strong>{Object.keys(inventory.detected).length}</strong>
                  </div>
                </div>
                <div className="artifact-table">
                  <div className="artifact-row head">
                    <span>ARTIFACT</span>
                    <span>TYPE</span>
                    <span>SIZE</span>
                    <span>ACTION</span>
                  </div>
                  {inventory.artifacts.slice(0, 500).map((item, index) => (
                    <div className="artifact-row" key={`${item.path}-${index}`}>
                      <span title={readablePath(item.path)}>
                        {readablePath(item.path)}
                      </span>
                      <span>{item.kind}</span>
                      <span>{humanSize(item.size)}</span>
                      <button
                        disabled={busy || !item.parser}
                        onClick={() => runParser(item)}
                      >
                        <Play size={13} />
                        Parse
                      </button>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
        {activeCase && view === "jobs" && (
          <section className="results jobs-view">
            <div className="jobs-heading">
              <div>
                <small>PARSER JOBS</small>
                <h2>Processing history</h2>
              </div>
              {activeJobId && (
                <button className="stop-job" onClick={cancelActiveJob}>
                  <Square size={13} />
                  Stop current job
                </button>
              )}
            </div>
            {jobs.length === 0 ? (
              <p className="empty-state">
                No parser jobs have been run for this case.
              </p>
            ) : (
              <div className="job-list">
                {jobs.map((job) => (
                  <article key={job.job_id}>
                    <span className={`job-state ${job.status}`}>
                      {job.status.replace("_", " ")}
                    </span>
                    <div>
                      <strong>{job.parser}</strong>
                      <p>{job.message}</p>
                      <small>
                        {job.phase} ·{" "}
                        {new Date(job.started_utc).toLocaleString()}
                        {job.normalized_events
                          ? ` · ${job.normalized_events.toLocaleString()} events`
                          : ""}
                      </small>
                    </div>
                    <code title={readablePath(job.output ?? job.input)}>
                      {readablePath(job.output ?? job.input)}
                    </code>
                  </article>
                ))}
              </div>
            )}
          </section>
        )}
        {activeCase && view === "detections" && (
          <section className="detection-console">
            <div className="detection-statusbar">
              <div className="engine-state">
                <i className={detectionStatus?.ready ? "ready" : "offline"} />
                <div>
                  <strong>
                    {detectionStatus?.ready
                      ? "Detection engines ready"
                      : "Rule engines unavailable"}
                  </strong>
                  <span>
                    YARA · Hayabusa / Sigma · Chainsaw · VampHunt
                    correlation
                  </span>
                </div>
              </div>
              <div className="detection-metrics">
                <span>
                  <small>FILE RULES</small>
                  <b>{detectionStatus?.yara_rules.toLocaleString() ?? "—"}</b>
                </span>
                <span>
                  <small>EVENT RULES</small>
                  <b>
                    {detectionStatus
                      ? (
                          detectionStatus.sigma_rules +
                          detectionStatus.hayabusa_rules
                        ).toLocaleString()
                      : "—"}
                  </b>
                </span>
                <span>
                  <small>ARTIFACT RULES</small>
                  <b>
                    {detectionStatus
                      ? (
                          detectionStatus.chainsaw_rules +
                          detectionStatus.correlation_rules
                        ).toLocaleString()
                      : "—"}
                  </b>
                </span>
                <span>
                  <small>SAVED LEADS</small>
                  <b>{detectionLeads.length.toLocaleString()}</b>
                </span>
              </div>
            </div>

            <div className="scan-command">
              <div className="scan-copy">
                <strong>Analyze collected evidence</strong>
                <span>
                  Run the registered detection layers against this case and
                  preserve matched source context.
                </span>
              </div>
              <div className="scan-input">
                <PathField
                  value={evidencePath}
                  onChange={setEvidencePath}
                  placeholder="Collected evidence directory"
                  aria-label="Evidence directory to scan"
                  browseTitle="Choose evidence folder to analyze"
                  disabled={busy}
                  onError={setMessage}
                />
                <button
                  disabled={
                    busy || !detectionStatus?.ready || !evidencePath.trim()
                  }
                  onClick={runDetections}
                >
                  <Radar size={15} />
                  Analyze evidence
                </button>
              </div>
            </div>

            <div className="lead-workbench">
              <div className="lead-toolbar">
                <div>
                  <strong>Rule matches</strong>
                  <span>
                    Leads are triage signals. Confirm source evidence before
                    creating a finding.
                  </span>
                </div>
                <div className="lead-search">
                  <Search size={14} />
                  <input
                    placeholder="Search rule, engine, target…"
                    value={leadSearch}
                    onChange={(event) => setLeadSearch(event.target.value)}
                  />
                </div>
              </div>

              <div className="severity-tabs">
                {["All", "Critical", "High", "Medium", "Low"].map((severity) => {
                  const count =
                    severity === "All"
                      ? detectionLeads.length
                      : (leadSeverityCounts[severity.toLowerCase()] ?? 0);
                  return (
                    <button
                      key={severity}
                      className={leadSeverity === severity ? "active" : ""}
                      onClick={() => setLeadSeverity(severity)}
                    >
                      {severity}
                      <span>{count}</span>
                    </button>
                  );
                })}
              </div>

              <section className="lead-list-modern">
                {visibleDetectionLeads.length === 0 ? (
                  <p className="empty-state">
                    No rule matches match the current view.
                  </p>
                ) : (
                  visibleDetectionLeads.map((lead) => (
                    <article
                      className={`lead-row lead-${lead.severity.toLowerCase()}`}
                      key={lead.id}
                    >
                      <div className="lead-severity-rail">
                        <span>{lead.severity}</span>
                      </div>
                      <div className="lead-body">
                        <div className="lead-titleline">
                          <strong>{lead.title}</strong>
                          <span className="lead-engine">{lead.engine}</span>
                        </div>
                        <code className="lead-target">{lead.target}</code>
                        <div className="lead-meta">
                          <span>
                            Rule <b>{lead.rule_id}</b>
                          </span>
                          <span>{lead.source}</span>
                          {lead.supporting_events > 0 && (
                            <span>
                              {lead.supporting_events.toLocaleString()} linked
                              event
                              {lead.supporting_events === 1 ? "" : "s"}
                            </span>
                          )}
                        </div>
                        <details className="lead-source">
                          <summary>Inspect matched source</summary>
                          <pre>{lead.raw}</pre>
                        </details>
                      </div>
                    </article>
                  ))
                )}
              </section>
            </div>
          </section>
        )}
        {activeCase && view === "explorer" && (
          <section
            className={`explorer-layout ${sourceRecord ? "with-source" : ""}`}
          >
            <section className="explorer-workbench">
              <div className="explorer-commandbar">
                <div className="event-search-field">
                  <Search size={15} />
                  <input
                    placeholder="Search across every normalized field"
                    value={eventFilter.search}
                    onChange={(event) =>
                      setEventFilter({
                        ...eventFilter,
                        search: event.target.value,
                      })
                    }
                    onKeyDown={(event) => {
                      if (event.key === "Enter")
                        applyEventFilter({ ...eventFilter, page: 0 });
                    }}
                  />
                  <kbd>Enter</kbd>
                </div>
                <button
                  className="event-search-button"
                  onClick={() => applyEventFilter({ ...eventFilter, page: 0 })}
                >
                  Search
                </button>
                <button
                  className={`filter-toggle ${showFilters ? "active" : ""}`}
                  onClick={() => setShowFilters((value) => !value)}
                >
                  <SlidersHorizontal size={14} />
                  Filters
                  {activeEventFilterCount > 0 && (
                    <span>{activeEventFilterCount}</span>
                  )}
                </button>
                <div className="event-command-meta">
                  <b>{eventPage.total.toLocaleString()}</b>
                  <span>normalized records</span>
                </div>
              </div>

              {showFilters && (
                <div className="filter-workbench">
                  <div className="filter-grid">
                    <div className="filter-field">
                      <label>Artifact type</label>
                      <MultiFilter
                        label="Any artifact"
                        options={filterOptions.artifact_types}
                        selected={eventFilter.artifact_type}
                        onChange={(artifact_type) =>
                          setEventFilter({ ...eventFilter, artifact_type })
                        }
                      />
                    </div>
                    <div className="filter-field">
                      <label>Event type</label>
                      <MultiFilter
                        label="Any event"
                        options={filterOptions.event_types}
                        selected={eventFilter.event_type}
                        onChange={(event_type) =>
                          setEventFilter({ ...eventFilter, event_type })
                        }
                      />
                    </div>
                    <div className="filter-field">
                      <label>Host</label>
                      <MultiFilter
                        label="Any host"
                        options={filterOptions.hosts}
                        selected={eventFilter.host}
                        onChange={(host) =>
                          setEventFilter({ ...eventFilter, host })
                        }
                      />
                    </div>
                    <div className="filter-field">
                      <label>User</label>
                      <MultiFilter
                        label="Any user"
                        options={filterOptions.users}
                        selected={eventFilter.user}
                        onChange={(user) =>
                          setEventFilter({ ...eventFilter, user })
                        }
                      />
                    </div>
                    <label className="filter-field date-filter">
                      <span>From UTC</span>
                      <input
                        type="datetime-local"
                        value={eventFilter.from_utc}
                        onChange={(event) =>
                          setEventFilter({
                            ...eventFilter,
                            from_utc: event.target.value,
                          })
                        }
                      />
                    </label>
                    <label className="filter-field date-filter">
                      <span>To UTC</span>
                      <input
                        type="datetime-local"
                        value={eventFilter.to_utc}
                        onChange={(event) =>
                          setEventFilter({
                            ...eventFilter,
                            to_utc: event.target.value,
                          })
                        }
                      />
                    </label>
                  </div>

                  <div className="filter-footer">
                    <details className="column-config">
                      <summary>
                        <Rows3 size={14} />
                        Columns
                        <span>{visibleColumns.length} visible</span>
                      </summary>
                      <div className="column-picks">
                        {[
                          "time",
                          "type",
                          "host",
                          "user",
                          "process",
                          "path",
                          "summary",
                          "source",
                        ].map((column) => (
                          <label key={column}>
                            <input
                              type="checkbox"
                              checked={visibleColumns.includes(column)}
                              onChange={() => toggleColumn(column)}
                            />
                            {column}
                          </label>
                        ))}
                      </div>
                    </details>
                    <div className="filter-actions">
                      <button
                        className="clear-filter"
                        onClick={() => {
                          const clean = {
                            search: "",
                            artifact_type: [],
                            event_type: [],
                            host: [],
                            user: [],
                            from_utc: "",
                            to_utc: "",
                            page: 0,
                            page_size: eventFilter.page_size,
                          };
                          applyEventFilter(clean);
                        }}
                      >
                        Clear all
                      </button>
                      <button
                        className="apply-filter"
                        onClick={() =>
                          applyEventFilter({ ...eventFilter, page: 0 })
                        }
                      >
                        Apply filters
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <div className="event-context-strip">
                <div className="event-view-stats">
                  <span>
                    Showing <b>{events.length.toLocaleString()}</b> rows
                  </span>
                  <i />
                  <span>
                    Page <b>{eventPage.page + 1}</b> of{" "}
                    <b>
                      {Math.max(
                        1,
                        Math.ceil(eventPage.total / eventPage.page_size),
                      )}
                    </b>
                  </span>
                  {selectedEvents.length > 0 && (
                    <>
                      <i />
                      <span className="selected-count">
                        <b>{selectedEvents.length}</b> selected for findings
                      </span>
                    </>
                  )}
                </div>
                <div className="density-control">
                  <span>Density</span>
                  <button
                    className={eventDensity === "compact" ? "active" : ""}
                    onClick={() => setEventDensity("compact")}
                  >
                    Compact
                  </button>
                  <button
                    className={eventDensity === "comfortable" ? "active" : ""}
                    onClick={() => setEventDensity("comfortable")}
                  >
                    Comfortable
                  </button>
                </div>
              </div>

              <div className={`event-table event-table-${eventDensity}`}>
                <div className="event-row event-head">
                  <span className="row-actions">ACTIONS</span>
                  {visibleColumns.includes("time") && (
                    <span className="event-time">TIME UTC</span>
                  )}
                  {visibleColumns.includes("type") && (
                    <span className="event-kind">TYPE</span>
                  )}
                  {visibleColumns.includes("host") && (
                    <span className="event-entity">HOST</span>
                  )}
                  {visibleColumns.includes("user") && (
                    <span className="event-entity">USER</span>
                  )}
                  {visibleColumns.includes("process") && (
                    <span className="event-process">PROCESS</span>
                  )}
                  {visibleColumns.includes("path") && (
                    <span className="event-path">PATH</span>
                  )}
                  {visibleColumns.includes("summary") && (
                    <span className="event-summary">EVENT</span>
                  )}
                  {visibleColumns.includes("source") && (
                    <span className="event-source">SOURCE</span>
                  )}
                </div>
                {events.map((event) => (
                  <div
                    className={`event-row ${selectedEvents.includes(event.id) ? "selected" : ""}`}
                    key={event.id}
                  >
                    <span className="row-actions">
                      <button
                        className={
                          selectedEvents.includes(event.id)
                            ? "select-row active"
                            : "select-row"
                        }
                        title="Add event to finding selection"
                        onClick={() => toggleEvent(event.id)}
                      >
                        {selectedEvents.includes(event.id) ? (
                          <Check size={12} />
                        ) : (
                          "+"
                        )}
                      </button>
                      <button
                        className="inspect-row"
                        title="Inspect original parser record"
                        onClick={() => inspectEvent(event.id)}
                      >
                        <Eye size={12} />
                        View
                      </button>
                    </span>
                    {visibleColumns.includes("time") && (
                      <span className="event-time">
                        {event.timestamp_utc ?? "—"}
                      </span>
                    )}
                    {visibleColumns.includes("type") && (
                      <span className="event-kind">{event.event_type}</span>
                    )}
                    {visibleColumns.includes("host") && (
                      <span className="event-entity">{event.host ?? "—"}</span>
                    )}
                    {visibleColumns.includes("user") && (
                      <span className="event-entity">{event.user ?? "—"}</span>
                    )}
                    {visibleColumns.includes("process") && (
                      <span className="event-process">
                        {event.process ?? "—"}
                      </span>
                    )}
                    {visibleColumns.includes("path") && (
                      <span className="event-path" title={event.path ?? ""}>
                        {event.path ?? "—"}
                      </span>
                    )}
                    {visibleColumns.includes("summary") && (
                      <span className="event-summary" title={event.summary}>
                        {event.summary}
                      </span>
                    )}
                    {visibleColumns.includes("source") && (
                      <span className="event-source">
                        {event.source_table}
                        <small>{event.source_row_id}</small>
                      </span>
                    )}
                  </div>
                ))}
              </div>

              <div className="pager">
                <label className="page-size-control">
                  Rows
                  <select
                    value={eventFilter.page_size}
                    onChange={(event) =>
                      applyEventFilter({
                        ...eventFilter,
                        page: 0,
                        page_size: Number(event.target.value),
                      })
                    }
                  >
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={250}>250</option>
                    <option value={500}>500</option>
                  </select>
                </label>
                <span>
                  {(eventPage.page * eventPage.page_size + 1).toLocaleString()}–
                  {Math.min(
                    (eventPage.page + 1) * eventPage.page_size,
                    eventPage.total,
                  ).toLocaleString()}{" "}
                  of {eventPage.total.toLocaleString()}
                </span>
                <button
                  disabled={eventPage.page === 0}
                  onClick={() =>
                    applyEventFilter({
                      ...eventFilter,
                      page: eventPage.page - 1,
                    })
                  }
                >
                  <ChevronLeft size={14} />
                  Previous
                </button>
                <button
                  disabled={
                    (eventPage.page + 1) * eventPage.page_size >=
                    eventPage.total
                  }
                  onClick={() =>
                    applyEventFilter({
                      ...eventFilter,
                      page: eventPage.page + 1,
                    })
                  }
                >
                  Next
                  <ChevronRight size={14} />
                </button>
              </div>
            </section>

            {sourceRecord && (
              <aside className="source-panel source-panel-modern">
                <div className="source-panel-head">
                  <div>
                    <small>ORIGINAL PARSER RECORD</small>
                    <h3>{sourceRecord.table}</h3>
                  </div>
                  <button
                    aria-label="Close source record"
                    onClick={() => setSourceRecord(null)}
                  >
                    <X size={15} />
                  </button>
                </div>
                <div className="source-reference">
                  <span>Row reference</span>
                  <code>{sourceRecord.row_reference}</code>
                </div>
                <div className="source-reference">
                  <span>Database</span>
                  <code>{readablePath(sourceRecord.database)}</code>
                </div>
                <dl>
                  {Object.entries(sourceRecord.fields).map(([key, value]) => (
                    <div key={key}>
                      <dt>{key}</dt>
                      <dd>
                        {value === null
                          ? "NULL"
                          : typeof value === "object"
                            ? JSON.stringify(value)
                            : String(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </aside>
            )}
          </section>
        )}
        {activeCase && view === "connections" && (
          <section className="graph-workspace">
            <div className="graph-context-bar">
              <div>
                <strong>Relationship map</strong>
                <span>
                  {relationships.length.toLocaleString()} relationships loaded
                  {overview
                    ? ` · ${overview.entities.toLocaleString()} entities in case`
                    : ""}
                </span>
              </div>
              <span>
                Drag to pan · wheel to zoom · click a node to isolate context
              </span>
            </div>
            <section className="graph-results">
              <Suspense
                fallback={<div className="graph-loading">Building graph…</div>}
              >
                <GraphView relationships={relationships} />
              </Suspense>
            </section>
          </section>
        )}
        {activeCase && view === "report" && (
          <section className="report-workspace">
            <div className="report-tabs" role="tablist" aria-label="Report workspace">
              <button
                type="button"
                role="tab"
                aria-selected={reportTab === "findings"}
                className={reportTab === "findings" ? "active" : ""}
                onClick={() => setReportTab("findings")}
              >
                Manual findings
                <span>{findings.length}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={reportTab === "build"}
                className={reportTab === "build" ? "active" : ""}
                onClick={() => setReportTab("build")}
              >
                Build report
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={reportTab === "generated"}
                className={reportTab === "generated" ? "active" : ""}
                onClick={() => {
                  setReportTab("generated");
                  void refreshGeneratedReports();
                }}
              >
                Generated reports
                <span>{generatedReports.length}</span>
              </button>
            </div>

            {reportTab === "findings" && (
              <section className="report-tab-panel manual-findings-panel" role="tabpanel">
                <div className="inner-panel-heading">
                  <div>
                    <small>MANUAL FINDINGS</small>
                    <h2>Analyst-reviewed findings</h2>
                    <p>
                      Select supporting records in Event explorer, then document
                      the conclusion here.
                    </p>
                  </div>
                </div>
                <section className="findings-grid">
                  <article className="case-picker">
                    <label>
                      NEW FINDING · {selectedEvents.length} SUPPORTING EVENTS
                    </label>
                    <input
                      placeholder="Finding title"
                      value={findingTitle}
                      onChange={(e) => setFindingTitle(e.target.value)}
                    />
                    <select
                      value={findingSeverity}
                      onChange={(e) => setFindingSeverity(e.target.value)}
                    >
                      <option>Low</option>
                      <option>Medium</option>
                      <option>High</option>
                      <option>Critical</option>
                    </select>
                    <textarea
                      placeholder="Analyst notes"
                      value={findingNotes}
                      onChange={(e) => setFindingNotes(e.target.value)}
                    />
                    <button
                      disabled={
                        busy || !findingTitle.trim() || selectedEvents.length === 0
                      }
                      onClick={createFinding}
                    >
                      Create finding
                    </button>
                  </article>
                  <section className="results finding-list">
                    {findings.length === 0 ? (
                      <div className="report-empty-state">
                        No manual findings have been created for this case.
                      </div>
                    ) : (
                      findings.map((finding) => (
                        <article key={finding.id}>
                          <span
                            className={`severity ${finding.severity.toLowerCase()}`}
                          >
                            {finding.severity}
                          </span>
                          <div>
                            <strong>{finding.title}</strong>
                            <p>{finding.notes}</p>
                            <small>
                              {finding.status} · {finding.evidence_count} supporting
                              events
                            </small>
                            <div className="review-actions">
                              {finding.status !== "Confirmed" && (
                                <button
                                  onClick={() =>
                                    setFindingStatus(finding.id, "Confirmed")
                                  }
                                >
                                  Confirm
                                </button>
                              )}
                              {finding.status !== "Closed" && (
                                <button
                                  onClick={() =>
                                    setFindingStatus(finding.id, "Closed")
                                  }
                                >
                                  Close
                                </button>
                              )}
                            </div>
                          </div>
                        </article>
                      ))
                    )}
                  </section>
                </section>
              </section>
            )}

            {reportTab === "build" && (
              <section className="report-tab-panel report-builder" role="tabpanel">
                <div className="report-top">
                  <div>
                    <small>REPORT CONTENT</small>
                    <h2>Choose what to include</h2>
                    <p>
                      Select result types and severity levels. Every matching item
                      is included automatically.
                    </p>
                  </div>
                  <div>
                    <button disabled={busy} onClick={exportTimeline}>
                      Export event CSV
                    </button>
                    <button
                      disabled={busy || includedReportItems === 0}
                      onClick={generateReport}
                    >
                      Generate HTML report
                    </button>
                  </div>
                </div>

                <section className="report-filter-card">
                  <div className="report-filter-group">
                    <div className="report-filter-copy">
                      <small>RESULT TYPES</small>
                      <strong>Include in report</strong>
                    </div>
                    <div className="report-type-options">
                      <button
                        type="button"
                        aria-pressed={includeReportFindings}
                        className={includeReportFindings ? "selected" : ""}
                        onClick={() => setIncludeReportFindings((value) => !value)}
                      >
                        <span><strong>Manual findings</strong><small>{findings.length} available</small></span>
                        <b>{includeReportFindings ? "Included" : "Excluded"}</b>
                      </button>
                      <button
                        type="button"
                        aria-pressed={includeReportLeads}
                        className={includeReportLeads ? "selected" : ""}
                        onClick={() => setIncludeReportLeads((value) => !value)}
                      >
                        <span><strong>Rule matches</strong><small>{detectionLeads.length} available</small></span>
                        <b>{includeReportLeads ? "Included" : "Excluded"}</b>
                      </button>
                    </div>
                  </div>

                  <div className="report-filter-group">
                    <div className="report-filter-copy">
                      <small>SEVERITY</small>
                      <strong>Choose severity levels</strong>
                    </div>
                    <div className="report-severity-options">
                      {reportSeverityOptions.map((severity) => (
                        <button
                          type="button"
                          key={severity}
                          aria-pressed={reportSeverities.includes(severity)}
                          className={
                            reportSeverities.includes(severity) ? "selected" : ""
                          }
                          onClick={() => toggleReportSeverity(severity)}
                        >
                          <span className={`severity ${severity.toLowerCase()}`}>
                            {severity}
                          </span>
                          <strong>
                            {reportSeverityCounts[severity] ?? 0} available
                          </strong>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="report-selection-summary">
                    <div>
                      <strong>{includedReportItems.toLocaleString()}</strong>
                      <span>items included</span>
                    </div>
                    <div>
                      <strong>{excludedReportItems.toLocaleString()}</strong>
                      <span>items excluded</span>
                    </div>
                    <p>
                      {includedReportFindings.length.toLocaleString()} findings ·{" "}
                      {includedReportLeads.length.toLocaleString()} rule matches
                    </p>
                  </div>
                </section>
              </section>
            )}

            {reportTab === "generated" && (
              <section className="report-tab-panel generated-reports-panel" role="tabpanel">
                <div className="inner-panel-heading">
                  <div>
                    <small>GENERATED REPORTS</small>
                    <h2>Saved report files</h2>
                    <p>HTML reports and timeline CSV exports stored in this case.</p>
                  </div>
                  <button disabled={busy} onClick={() => void refreshGeneratedReports()}>
                    Refresh
                  </button>
                </div>
                <div className="generated-report-list">
                  {generatedReports.length === 0 ? (
                    <div className="report-empty-state">
                      No reports have been generated for this case.
                    </div>
                  ) : (
                    generatedReports.map((item) => (
                      <article key={item.path}>
                        <div className="report-file-icon"><FileText size={18} /></div>
                        <div className="report-file-details">
                          <strong>{item.name}</strong>
                          <small>
                            {item.kind} · {humanSize(item.bytes)} · {displayUtc(item.modified_utc)}
                          </small>
                          <code title={readablePath(item.path)}>
                            {readablePath(item.path)}
                          </code>
                        </div>
                        <div className="generated-report-actions">
                          <button
                            disabled={busy}
                            onClick={() => void openGeneratedReport(item)}
                          >
                            <ExternalLink size={14} /> Open
                          </button>
                          <button
                            disabled={busy}
                            onClick={() => void revealGeneratedReport(item)}
                          >
                            <FolderOpen size={14} /> Show in Explorer
                          </button>
                          <button
                            className="delete-report"
                            disabled={busy}
                            onClick={() => requestReportDeletion(item)}
                          >
                            <Trash2 size={14} /> Delete
                          </button>
                        </div>
                      </article>
                    ))
                  )}
                </div>
              </section>
            )}

            {reportToDelete && (
              <div className="case-dialog">
                <article className="case-picker delete-case-dialog delete-report-dialog">
                  <button
                    type="button"
                    className="dialog-close"
                    aria-label="Close"
                    title="Close"
                    disabled={busy}
                    onClick={cancelReportDeletion}
                  >
                    <X size={16} strokeWidth={1.5} />
                  </button>
                  <label>DELETE GENERATED FILE</label>
                  <h2>{reportToDelete.name}</h2>
                  <p>
                    This permanently deletes the selected file from this case's
                    REPORTS folder.
                  </p>
                  <code className="delete-case-path">
                    {readablePath(reportToDelete.path)}
                  </code>
                  {reportDeleteError && (
                    <p className="delete-case-error">{reportDeleteError}</p>
                  )}
                  <div className="delete-case-actions">
                    <button
                      type="button"
                      className="delete-cancel"
                      disabled={busy}
                      onClick={cancelReportDeletion}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="delete-confirm"
                      disabled={busy}
                      onClick={() => void deleteGeneratedReport()}
                    >
                      <Trash2 size={15} />
                      {busy ? "Deleting…" : "Delete file"}
                    </button>
                  </div>
                </article>
              </div>
            )}
          </section>
        )}
        <div className="status-line">{readablePath(message)}</div>
      </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
