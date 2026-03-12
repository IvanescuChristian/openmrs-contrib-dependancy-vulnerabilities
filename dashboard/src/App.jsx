import React, { useState, useMemo } from 'react';
import JSZip from 'jszip';
import './App.css';
import billingData from './data/openmrs-module-billing.json';
import coreData from './data/openmrs-core.json';
import idgenData from './data/openmrs-module-idgen.json';

const SEVERITY_WEIGHT = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0 };

const compareVersions = (v1, v2) => {
    if (v1 === '-' && v2 === '-') return 0;
    if (v1 === '-') return -1;
    if (v2 === '-') return 1;
    return v1.localeCompare(v2, undefined, { numeric: true, sensitivity: 'base' });
};

const extractSafe = (val) => (val !== undefined && val !== null && val !== '') ? val : '-';

const processRepo = (rawData, name) => {
    const vulnerabilities = rawData.vulnerabilities || [];
    const grouped = vulnerabilities.reduce((acc, v) => {
        const pkgName = v.location?.dependency?.package?.name || 'unknown';
        if (!acc[pkgName]) {
            acc[pkgName] = { name: pkgName, version: extractSafe(v.location?.dependency?.version), vulns: [], maxScore: 0 };
        }
        const score = v.cvssScore || v.score || (SEVERITY_WEIGHT[v.severity] * 2.5);
        const severityWeight = SEVERITY_WEIGHT[v.severity] || 0;
        if (score > acc[pkgName].maxScore) acc[pkgName].maxScore = score;
        acc[pkgName].vulns.push({
            id: extractSafe(v.id),
            severity: extractSafe(v.severity),
            severityWeight: severityWeight,
            score: extractSafe(v.cvssScore || v.score),
            description: extractSafe(v.description),
            affected: extractSafe(v.vulnerableVersions || v.vulnerable_versions),
            fixedIn: extractSafe(v.fixedIn || v.fixed_in),
            cwe: extractSafe(v.cwe || (v.cwes ? v.cwes[0] : null)),
            exploit: extractSafe(v.exploit)
        });
        return acc;
    }, {});

    const deps = Object.values(grouped).map(dep => {
        const validFixes = dep.vulns.map(v => v.fixedIn).filter(f => f !== '-');
        const highestFix = validFixes.length > 0 ? validFixes.sort(compareVersions).pop() : '-';
        dep.vulns.sort((a, b) => b.severityWeight - a.severityWeight);
        return { ...dep, fixVersion: highestFix };
    });

    deps.sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
    const repoMaxScore = Math.max(...deps.map(d => d.maxScore), 0);
    const repoSeverity = deps.length > 0 ? deps[0].vulns[0].severity : 'None';

    return { name, maxScore: repoMaxScore, maxSeverity: repoSeverity, dependencies: deps };
};

async function fetchLiveRepoData(repoName, token) {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
        const runsRes = await fetch(`https://api.github.com/repos/openmrs/${repoName}/actions/runs?status=success&per_page=30`, { headers });
        if (!runsRes.ok) throw new Error(`API error for ${repoName}`);
        const runsData = await runsRes.json();
        if (!runsData.workflow_runs || runsData.workflow_runs.length === 0) return null;

        let targetArtifact = null;
        for (const run of runsData.workflow_runs) {
            const artifactsRes = await fetch(run.artifacts_url, { headers });
            const artifactsData = await artifactsRes.json();
            if (artifactsData.artifacts && artifactsData.artifacts.length > 0) {
                targetArtifact = artifactsData.artifacts.find(a =>
                    a.name.toLowerCase().includes('report') || a.name.toLowerCase().includes('dependency')
                );
                if (targetArtifact) break;
            }
        }

        if (!targetArtifact) return null;

        const zipRes = await fetch(targetArtifact.archive_download_url, { headers });
        if (!zipRes.ok) throw new Error('Download failed');
        const zipBlob = await zipRes.blob();
        const zip = await JSZip.loadAsync(zipBlob);

        let jsonContent = null;
        const expectedPath = `${repoName}/vulnerability-report.json`;

        if (zip.files[expectedPath]) {
            jsonContent = await zip.files[expectedPath].async('string');
        } else {
            const jsonFile = Object.values(zip.files).find(f => !f.dir && f.name.endsWith('.json'));
            if (jsonFile) jsonContent = await jsonFile.async('string');
        }

        return jsonContent ? JSON.parse(jsonContent) : null;
    } catch (error) {
        return null;
    }
}

const SeverityPill = ({ severity }) => {
    if (!severity || severity === '-' || severity === 'None') return null;
    const styles = { 'Critical': { bg: '#ff8a8a', text: '#5a0000' }, 'High': { bg: '#ffc6c6', text: '#7a0000' }, 'Medium': { bg: '#ffe58f', text: '#5c4300' }, 'Low': { bg: '#d6e4ff', text: '#002c8c' } };
    const s = styles[severity] || styles['Low'];
    return <span style={{ backgroundColor: s.bg, color: s.text, padding: '4px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: '600', display: 'inline-block' }}>{severity}</span>;
};

const SortableHeader = ({ label, sortKey, sortQueue, onSort }) => {
    const queueIdx = sortQueue.findIndex(q => q.key === sortKey);
    const isActive = queueIdx >= 0;
    const sortOrder = isActive ? sortQueue[queueIdx].order : null;
    const priorityLabel = sortQueue.length > 0 && isActive ? ` (${queueIdx + 1})` : '';

    return (
        <div onClick={() => onSort(sortKey)} style={{ display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer', userSelect: 'none', color: isActive ? '#0f62fe' : '#161616', fontWeight: '600' }}>
            {label} <span style={{ fontSize: '10px', color: '#0f62fe', fontWeight: 'bold' }}>{priorityLabel}</span>
            <span style={{ fontSize: '10px', color: isActive ? '#0f62fe' : '#a8a8a8' }}>
                {isActive ? (sortOrder === 'desc' ? '▼' : '▲') : '↕'}
            </span>
        </div>
    );
};

const depGridTemplate = "3fr 1.5fr 1.5fr 1fr 1fr 1.5fr";
const cveGridTemplate = "1.5fr 1fr 1fr 3fr 1.5fr 1fr 1fr";

function DependencyRow({ dep }) {
    const [isOpen, setIsOpen] = useState(false);
    const [cveSortQueue, setCveSortQueue] = useState([]);

    const handleCveSort = (key) => {
        setCveSortQueue(prev => {
            const existingIdx = prev.findIndex(item => item.key === key);
            if (existingIdx >= 0) {
                const newOrder = prev[existingIdx].order === 'desc' ? 'asc' : 'desc';
                const newQueue = prev.filter((_, idx) => idx !== existingIdx);
                newQueue.push({ key, order: newOrder });
                return newQueue;
            }
            return [...prev, { key, order: 'desc' }];
        });
    };

    const sortedCves = useMemo(() => {
        if (cveSortQueue.length === 0) {
            return [...dep.vulns].sort((a, b) => b.severityWeight - a.severityWeight);
        }
        return [...dep.vulns].sort((a, b) => {
            for (const sortItem of cveSortQueue) {
                let valA = a[sortItem.key];
                let valB = b[sortItem.key];
                if (valA === '-') valA = '';
                if (valB === '-') valB = '';

                if (typeof valA === 'number' && typeof valB === 'number') {
                    if (valA !== valB) return sortItem.order === 'desc' ? valB - valA : valA - valB;
                } else {
                    const cmp = String(valA).localeCompare(String(valB), undefined, { numeric: true });
                    if (cmp !== 0) return sortItem.order === 'desc' ? -cmp : cmp;
                }
            }
            return 0;
        });
    }, [dep.vulns, cveSortQueue]);

    return (
        <div style={{ borderBottom: '1px solid #e0e0e0' }}>
            <div onClick={() => setIsOpen(!isOpen)} style={{ display: 'grid', gridTemplateColumns: depGridTemplate, alignItems: 'center', padding: '16px 24px', cursor: 'pointer', backgroundColor: isOpen ? '#fcfcfc' : '#fff', transition: 'background 0.2s' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}><span style={{ color: '#161616', fontSize: '12px', width: '16px' }}>{isOpen ? '⌃' : '⌄'}</span><span style={{ color: '#161616', fontSize: '14px', fontWeight: isOpen ? '600' : '400' }}>{dep.name}</span></div>
                <div style={{ color: '#333', fontSize: '13px' }}>{dep.version}</div><div><SeverityPill severity={dep.vulns[0].severity} /></div><div style={{ color: '#333', fontSize: '13px' }}>{dep.vulns.length}</div><div style={{ color: '#333', fontSize: '13px' }}>-</div><div style={{ color: '#333', fontSize: '13px' }}>{dep.fixVersion}</div>
            </div>
            {isOpen && (
                <div style={{ padding: '0 24px 24px 60px', backgroundColor: '#fcfcfc' }}>
                    <div style={{ border: '1px solid #e0e0e0', borderRadius: '4px', overflow: 'hidden' }}>

                        {cveSortQueue.length > 0 && (
                            <div style={{ padding: '8px 16px', backgroundColor: '#fdfdfd', borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'flex-end' }}>
                                <button onClick={() => setCveSortQueue([])} style={{ fontSize: '12px', color: '#da1e28', border: '1px solid #da1e28', background: 'transparent', padding: '4px 12px', borderRadius: '4px', cursor: 'pointer' }}>
                                    Reset Filters
                                </button>
                            </div>
                        )}

                        <div style={{ display: 'grid', gridTemplateColumns: cveGridTemplate, backgroundColor: '#f4f4f4', padding: '12px 16px', borderBottom: '1px solid #e0e0e0', fontSize: '13px' }}>
                            <SortableHeader label="CVE ID" sortKey="id" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="Severity" sortKey="severityWeight" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="Score" sortKey="score" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="Description" sortKey="description" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="Affected Versions" sortKey="affected" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="Fixed In" sortKey="fixedIn" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <SortableHeader label="CWE" sortKey="cwe" sortQueue={cveSortQueue} onSort={handleCveSort} />
                        </div>
                        {sortedCves.map(v => (
                            <div key={v.id} style={{ display: 'grid', gridTemplateColumns: cveGridTemplate, alignItems: 'start', padding: '16px', borderBottom: '1px solid #f0f0f0', fontSize: '13px', color: '#161616' }}>
                                <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer" style={{ color: '#0f62fe', textDecoration: 'underline' }}>{v.id}</a><div><SeverityPill severity={v.severity} /></div><div>{v.score !== '-' ? `${v.score}/10` : '-'}</div><div style={{ paddingRight: '20px', lineHeight: '1.4' }}>{v.description}</div><div>{v.affected}</div><div>{v.fixedIn}</div><div>{v.cwe}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

function RepoAccordion({ repo }) {
    const [isOpen, setIsOpen] = useState(false);
    const [depSortQueue, setDepSortQueue] = useState([]);

    const handleDepSort = (key) => {
        setDepSortQueue(prev => {
            const existingIdx = prev.findIndex(item => item.key === key);
            if (existingIdx >= 0) {
                const newOrder = prev[existingIdx].order === 'desc' ? 'asc' : 'desc';
                const newQueue = prev.filter((_, idx) => idx !== existingIdx);
                newQueue.push({ key, order: newOrder });
                return newQueue;
            }
            return [...prev, { key, order: 'desc' }];
        });
    };

    const getDepVal = (dep, key) => {
        if (key === 'cves') return dep.vulns.length;
        return dep[key];
    };

    const sortedDependencies = useMemo(() => {
        if (depSortQueue.length === 0) {
            return [...repo.dependencies].sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
        }
        return [...repo.dependencies].sort((a, b) => {
            for (const sortItem of depSortQueue) {
                let valA = getDepVal(a, sortItem.key);
                let valB = getDepVal(b, sortItem.key);

                if (valA === '-') valA = '';
                if (valB === '-') valB = '';

                if (typeof valA === 'number' && typeof valB === 'number') {
                    if (valA !== valB) return sortItem.order === 'desc' ? valB - valA : valA - valB;
                } else {
                    const cmp = String(valA).localeCompare(String(valB), undefined, { numeric: true });
                    if (cmp !== 0) return sortItem.order === 'desc' ? -cmp : cmp;
                }
            }
            return 0;
        });
    }, [repo.dependencies, depSortQueue]);

    return (
        <div style={{
            backgroundColor: 'white',
            border: '1px solid #e0e0e0',
            marginBottom: '24px',
            borderRadius: '8px',
            overflow: 'hidden',
            boxShadow: '0 2px 8px rgba(0,0,0,0.04)'
        }}>
            <div
                onClick={() => setIsOpen(!isOpen)}
                style={{
                    padding: '24px',
                    cursor: 'pointer',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    backgroundColor: isOpen ? '#ffffff' : '#f8f9fa',
                    borderBottom: isOpen ? '1px solid #e0e0e0' : 'none',
                    transition: 'background-color 0.2s'
                }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}><h2 style={{ margin: 0, fontSize: '20px', color: '#161616', fontWeight: '600' }}>{repo.name}</h2><SeverityPill severity={repo.maxSeverity} /></div><span style={{ fontSize: '16px', color: '#161616' }}>{isOpen ? '⌃' : '⌄'}</span>
            </div>
            {isOpen && (
                <div>
                    {depSortQueue.length > 0 && (
                        <div style={{ padding: '12px 24px', backgroundColor: '#fcfcfc', borderBottom: '1px solid #e0e0e0', display: 'flex', justifyContent: 'flex-end' }}>
                            <button onClick={() => setDepSortQueue([])} style={{ fontSize: '13px', color: '#da1e28', border: '1px solid #da1e28', background: 'transparent', padding: '6px 16px', borderRadius: '4px', cursor: 'pointer', fontWeight: '600' }}>
                                Reset Filters
                            </button>
                        </div>
                    )}
                    <div style={{ display: 'grid', gridTemplateColumns: depGridTemplate, backgroundColor: '#e0e0e0', padding: '16px 24px', fontSize: '14px' }}>
                        <SortableHeader label="Dependency" sortKey="name" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <SortableHeader label="Version" sortKey="version" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <SortableHeader label="Severity" sortKey="maxScore" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <SortableHeader label="CVEs" sortKey="cves" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <SortableHeader label="Exploit" sortKey="exploit" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <SortableHeader label="Fix Version" sortKey="fixVersion" sortQueue={depSortQueue} onSort={handleDepSort} />
                    </div>
                    {sortedDependencies.map(dep => <DependencyRow key={dep.name} dep={dep} />)}
                </div>
            )}
        </div>
    );
}

export default function App() {
    const staticReports = useMemo(() => {
        return [
            processRepo(coreData, 'openmrs-core'),
            processRepo(idgenData, 'openmrs-module-idgen'),
            processRepo(billingData, 'openmrs-module-billing')
        ].sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
    }, []);

    const [reports, setReports] = useState(staticReports);
    const [token, setToken] = useState(import.meta.env.VITE_GITHUB_TOKEN || '');
    const [isLoading, setIsLoading] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');
    const [fetchStatus, setFetchStatus] = useState(null);

    const handleFetchLive = async () => {
        setIsLoading(true);
        setErrorMsg('');
        setFetchStatus(null);
        try {
            const reposToFetch = [
                { name: 'openmrs-core', fallback: coreData },
                { name: 'openmrs-module-idgen', fallback: idgenData },
                { name: 'openmrs-module-billing', fallback: billingData }
            ];
            const liveDataResults = [];
            let successCount = 0;

            for (const repoConfig of reposToFetch) {
                const rawJson = await fetchLiveRepoData(repoConfig.name, token);

                if (rawJson) {
                    successCount++;
                    liveDataResults.push(processRepo(rawJson, repoConfig.name));
                } else {
                    liveDataResults.push(processRepo(repoConfig.fallback, repoConfig.name));
                }
            }

            liveDataResults.sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
            setReports(liveDataResults);

            if (successCount === reposToFetch.length) setFetchStatus('live');
            else if (successCount > 0) setFetchStatus('partial');
            else setFetchStatus('local');

        } catch (err) {
            setErrorMsg(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="app-container">
            <div className="dashboard-wrapper">
                <header className="app-header">
                    <h1 className="header-title">OpenMRS Dependency Vulnerability Report</h1>
                    <div className="header-divider"></div>
                    <p className="header-desc">A summary of known security vulnerabilities detected across OpenMRS modules.</p>
                </header>

                <div className="controls-panel">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, maxWidth: '400px' }}>
                        <label style={{ fontSize: '12px', fontWeight: '600', color: '#666' }}>GitHub AuthKey:</label>
                        <input
                            type="password"
                            value={token}
                            onChange={(e) => setToken(e.target.value)}
                            placeholder="ghp_xxxx"
                            autoComplete="new-password"
                            style={{ padding: '8px 12px', borderRadius: '4px', border: '1px solid #ccc' }}
                        />
                    </div>
                    <button onClick={handleFetchLive} disabled={isLoading || !token} style={{ padding: '10px 20px', backgroundColor: token ? '#0f62fe' : '#e0e0e0', color: token ? 'white' : '#888', border: 'none', borderRadius: '4px', cursor: token && !isLoading ? 'pointer' : 'not-allowed', fontWeight: '600', marginTop: '16px' }}>
                        {isLoading ? 'Loading...' : 'Fetch Live Data'}
                    </button>
                    {!isLoading && fetchStatus === 'live' && <span style={{ marginTop: '16px', color: '#24a148', fontWeight: 'bold' }}>Extracted Data</span>}
                    {!isLoading && fetchStatus === 'partial' && <span style={{ marginTop: '16px', color: '#f1c21b', fontWeight: 'bold' }}>Partial Extracted Data</span>}
                    {(!isLoading && fetchStatus === 'local') && <span style={{ marginTop: '16px', color: '#da1e28', fontWeight: 'bold' }}>Local Data</span>}
                    {(!isLoading && fetchStatus === null) && <span style={{ marginTop: '16px', color: '#666', fontWeight: 'bold' }}>Local Data</span>}
                </div>

                {errorMsg && <div style={{ backgroundColor: '#ffe5e5', color: '#da1e28', padding: '16px', borderRadius: '4px', marginBottom: '24px' }}>{errorMsg}</div>}
                {isLoading ? <div style={{ textAlign: 'center', padding: '50px', fontSize: '18px', color: '#666' }}>Fetching reports...</div> : reports.map(repo => <RepoAccordion key={repo.name} repo={repo} />)}
            </div>
        </div>
    );
}