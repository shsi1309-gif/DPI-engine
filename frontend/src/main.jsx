import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  Ban,
  Check,
  Download,
  Filter,
  Globe2,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldOff,
  Upload
} from 'lucide-react';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080';

function formatBytes(bytes) {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function uniqueValues(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

const emptyTotals = {
  totalPackets: 0,
  blockedPackets: 0,
  forwardedPackets: 0,
  blockedBytes: 0
};

function App() {
  const [websites, setWebsites] = useState([]);
  const [totals, setTotals] = useState(emptyTotals);
  const [selectedApps, setSelectedApps] = useState([]);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [inputFile, setInputFile] = useState('');
  const [outputFile, setOutputFile] = useState('');
  const uploadInputRef = useRef(null);

  useEffect(() => {
    analyzeTraffic(buildBlockRequest([]));
  }, []);

  const categories = useMemo(
    () => ['All', ...Array.from(new Set(websites.map((site) => site.category)))],
    [websites]
  );

  const filteredSites = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return websites.filter((site) => {
      const matchesCategory = category === 'All' || site.category === category;
      const matchesQuery =
        !normalizedQuery ||
        site.domain.toLowerCase().includes(normalizedQuery) ||
        site.app.toLowerCase().includes(normalizedQuery);
      return matchesCategory && matchesQuery;
    });
  }, [category, query, websites]);

  function buildBlockRequest(apps, sourceWebsites = websites) {
    const selected = new Set(apps);
    const matchingSites = sourceWebsites.filter((site) => selected.has(site.app));

    return {
      blockedApps: apps,
      blockedDomains: uniqueValues(matchingSites.map((site) => site.domain)),
      blockedIps: [],
      blockedDestinationIps: uniqueValues(matchingSites.map((site) => site.destinationIp))
    };
  }

  async function analyzeTraffic(blockRequest) {
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(blockRequest)
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'Backend analysis failed');
      }

      setWebsites(payload.websites || []);
      setTotals(payload.totals || emptyTotals);
      setInputFile(payload.inputFile || '');
      setOutputFile(payload.outputFile || '');
    } catch (err) {
      setError(err.message || 'Unable to connect to backend');
    } finally {
      setLoading(false);
    }
  }

  function toggleApp(app) {
    const next = selectedApps.includes(app)
      ? selectedApps.filter((selectedApp) => selectedApp !== app)
      : [...selectedApps, app];

    setSelectedApps(next);
    analyzeTraffic(buildBlockRequest(next));
  }

  function clearBlocks() {
    setSelectedApps([]);
    analyzeTraffic(buildBlockRequest([]));
  }

  async function exportFilteredPcap() {
    if (!outputFile || loading) {
      return;
    }

    setError('');
    try {
      const response = await fetch(`${API_BASE}/api/download`);
      if (!response.ok) {
        let message = 'Unable to download filtered PCAP';
        try {
          const payload = await response.json();
          message = payload.error || message;
        } catch {
          // Keep the generic message if the backend did not return JSON.
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'filtered-dashboard.pcap';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || 'Unable to download filtered PCAP');
    }
  }

  async function uploadPcap(file) {
    if (!file) {
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/api/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-File-Name': encodeURIComponent(file.name)
        },
        body: file
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'PCAP upload failed');
      }

      setSelectedApps([]);
      setWebsites(payload.websites || []);
      setTotals(payload.totals || emptyTotals);
      setInputFile(payload.inputFile || file.name);
      setOutputFile(payload.outputFile || '');
    } catch (err) {
      setError(err.message || 'Unable to upload PCAP file');
    } finally {
      setLoading(false);
      if (uploadInputRef.current) {
        uploadInputRef.current.value = '';
      }
    }
  }

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Deep Packet Inspection</p>
          <h1>Packet Analyzer Dashboard</h1>
        </div>
        <div className="topbar-actions">
          <span className={`api-status ${error ? 'offline' : 'online'}`}>
            {error ? 'Backend offline' : loading ? 'Analyzing' : 'Backend live'}
          </span>
          <button className="icon-button" aria-label="Refresh analysis" title="Refresh analysis" onClick={() => analyzeTraffic(buildBlockRequest(selectedApps))}>
            <RefreshCw size={18} />
          </button>
          <input
            ref={uploadInputRef}
            className="file-input"
            type="file"
            accept=".pcap,application/vnd.tcpdump.pcap,application/octet-stream"
            onChange={(event) => uploadPcap(event.target.files?.[0])}
          />
          <button
            className="icon-button"
            aria-label="Upload PCAP file"
            title="Upload PCAP file"
            onClick={() => uploadInputRef.current?.click()}
            disabled={loading}
          >
            <Upload size={18} />
          </button>
          <button
            className="primary-button"
            title={outputFile ? `Latest output: ${outputFile}` : 'Run analysis to create output'}
            onClick={exportFilteredPcap}
            disabled={loading || !outputFile}
          >
            <Download size={18} />
            Export filtered PCAP
          </button>
        </div>
      </section>

      {error && (
        <section className="error-banner">
          Start the Java backend at <strong>http://127.0.0.1:8080</strong>. Details: {error}
        </section>
      )}

      {inputFile && !error && (
        <section className="file-banner">
          Active PCAP: <strong>{inputFile}</strong>
        </section>
      )}

      <section className="metrics-grid" aria-label="Traffic summary">
        <Metric icon={<Activity size={20} />} label="Total packets" value={totals.totalPackets.toLocaleString()} />
        <Metric icon={<ShieldOff size={20} />} label="Blocked packets" value={totals.blockedPackets.toLocaleString()} />
        <Metric icon={<ShieldCheck size={20} />} label="Forwarded packets" value={totals.forwardedPackets.toLocaleString()} />
        <Metric icon={<Ban size={20} />} label="Blocked data" value={formatBytes(totals.blockedBytes)} />
      </section>

      <section className="dashboard-grid">
        <aside className="selector-panel" aria-label="Application blocking list">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Block Applications</p>
              <h2>Detected apps</h2>
            </div>
            <span className="count-badge">{selectedApps.length} selected</span>
          </div>

          <div className="toolbar">
            <label className="search-box">
              <Search size={17} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search app or website"
              />
            </label>
            <label className="select-box">
              <Filter size={17} />
              <select value={category} onChange={(event) => setCategory(event.target.value)}>
                {categories.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
          </div>

          <div className="website-list">
            {loading && websites.length === 0 && <div className="empty-state">Loading backend results...</div>}
            {!loading && filteredSites.length === 0 && <div className="empty-state">No websites found</div>}
            {filteredSites.map((site) => {
              const selected = selectedApps.includes(site.app);
              return (
                <button
                  className={`website-row ${selected ? 'selected' : ''}`}
                  key={site.id}
                  onClick={() => toggleApp(site.app)}
                  aria-pressed={selected}
                  disabled={loading}
                >
                  <span className="checkmark" aria-hidden="true">
                    {selected ? <Check size={16} /> : <Globe2 size={16} />}
                  </span>
                  <span>
                    <strong>{site.domain}</strong>
                    <small>{site.app} · {site.category}</small>
                  </span>
                  <span className={`risk ${site.risk.toLowerCase()}`}>{site.risk}</span>
                </button>
              );
            })}
          </div>
        </aside>

        <section className="results-panel" aria-label="Blocking result table">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Result</p>
              <h2>Traffic after selected blocks</h2>
            </div>
            <button className="secondary-button" onClick={clearBlocks} disabled={loading || selectedApps.length === 0}>
              Clear blocks
            </button>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Application</th>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Packets</th>
                  <th>Data</th>
                  <th>Flows</th>
                  <th>Last seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {websites.map((site) => {
                  const blocked = Boolean(site.blocked);
                  return (
                    <tr key={site.id} className={blocked ? 'blocked-row' : ''}>
                      <td>
                        <div className="domain-cell">
                          <Lock size={16} />
                          <span>{site.domain}</span>
                        </div>
                      </td>
                      <td>{site.app}</td>
                      <td>{site.protocol}</td>
                      <td>{site.sourceIp}</td>
                      <td>{site.destinationIp}:{site.port}</td>
                      <td>{site.packets.toLocaleString()}</td>
                      <td>{formatBytes(site.bytes)}</td>
                      <td>{site.flows}</td>
                      <td>{site.lastSeen}</td>
                      <td>
                        <span className={`status-pill ${blocked ? 'blocked' : 'allowed'}`}>
                          {blocked ? 'Blocked' : 'Allowed'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </section>
    </main>
  );
}

function Metric({ icon, label, value }) {
  return (
    <article className="metric-card">
      <span className="metric-icon">{icon}</span>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
      </div>
    </article>
  );
}

createRoot(document.getElementById('root')).render(<App />);
