import React, { useState, useMemo, useEffect } from 'react';
import JSZip from 'jszip';
import './App.css';

const localDataImports = import.meta.glob('./data/*.json', { eager: true });
const coreData = localDataImports['./data/openmrs-core.json']?.default || null;
const idgenData = localDataImports['./data/openmrs-module-idgen.json']?.default || null;
const billingData = localDataImports['./data/openmrs-module-billing.json']?.default || null;

const SEVERITY_WEIGHT = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0 };

const compareVersions = (v1, v2) => {
    if (v1 === '-' && v2 === '-') return 0;
    if (v1 === '-') return -1;
    if (v2 === '-') return 1;
    return v1.localeCompare(v2, undefined, { numeric: true, sensitivity: 'base' });
};

const processRepo = (rawData, name) => {
    const vulnerabilities = rawData.vulnerabilities || [];
    const grouped = vulnerabilities.reduce((acc, v) => {
        const pkgName = v.location?.dependency?.package?.name || 'unknown';
        const pkgVersion = v.location?.dependency?.version || '-';

        if (!acc[pkgName]) {
            acc[pkgName] = { name: pkgName, version: pkgVersion, vulns: [], maxScore: 0 };
        }

        const score = v.cvssScore || v.score || (SEVERITY_WEIGHT[v.severity] * 2.5);
        const severityWeight = SEVERITY_WEIGHT[v.severity] || 0;

        if (score > acc[pkgName].maxScore) acc[pkgName].maxScore = score;

        acc[pkgName].vulns.push({
            id: v.id || '-',
            severity: v.severity || '-',
            severityWeight: severityWeight,
            score: v.cvssScore || v.score || '-',
            description: v.description || '-',
            affected: v.vulnerableVersions || v.vulnerable_versions || '-',
            fixedIn: v.fixedIn || v.fixed_in || '-',
            cwe: v.cwe || (v.cwes ? v.cwes[0] : null) || '-',
            exploit: v.exploit || '-'
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

async function fetchLiveRepoData(repoName, browserToken, envToken) {
    const owner = 'IvanescuChristian';
    const repo = 'openmrs-contrib-dependancy-vulnerabilities';
    const basePath = 'dashboard/src';

    const fetchWithToken = async (currentToken, keySourceName) => {
        const headers = { 'Accept': 'application/vnd.github.v3.raw' };
        if (currentToken) headers['Authorization'] = `Bearer ${currentToken}`;

        try {
            const jsonUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${basePath}/data/${repoName}.json`;
            const jsonRes = await fetch(jsonUrl, { headers });

            if (jsonRes.ok) {
                return { data: await jsonRes.json(), extractMethod: 'JSON', keyUsed: keySourceName };
            } else if (jsonRes.status === 401 || jsonRes.status === 403) {
                throw new Error("TokenInvalid");
            }
        } catch (e) {
            if (e.message === "TokenInvalid") throw e;
        }

        try {
            const zipUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${basePath}/public/test.zip`;
            const zipRes = await fetch(zipUrl, { headers });

            if (zipRes.ok) {
                const zipBlob = await zipRes.blob();
                const zip = await JSZip.loadAsync(zipBlob);

                let jsonFile = Object.values(zip.files).find(f => !f.dir && f.name.includes(repoName) && f.name.endsWith('.json'));

                if (!jsonFile) {
                    jsonFile = Object.values(zip.files).find(f => !f.dir && f.name.endsWith('.json') && !f.name.includes('package'));
                }

                if (jsonFile) {
                    const jsonContent = await jsonFile.async('string');
                    return { data: JSON.parse(jsonContent), extractMethod: 'ZIP', keyUsed: keySourceName };
                }
            } else if (zipRes.status === 401 || zipRes.status === 403) {
                throw new Error("TokenInvalid");
            }
        } catch (e) {
            if (e.message === "TokenInvalid") throw e;
        }

        throw new Error("NotFound");
    };

    if (browserToken) {
        try {
            return await fetchWithToken(browserToken, 'Browser');
        } catch (e) {}
    }

    if (envToken && envToken !== browserToken) {
        try {
            return await fetchWithToken(envToken, '.env');
        } catch (e) {}
    }

    return null;
}

const SeverityType = ({ severity }) => {
    if (!severity || severity === '-' || severity === 'None') return null;
    const styles = { 'Critical': { bg: '#ff8a8a', text: '#5a0000' }, 'High': { bg: '#ffc6c6', text: '#7a0000' }, 'Medium': { bg: '#ffe58f', text: '#5c4300' }, 'Low': { bg: '#d6e4ff', text: '#002c8c' } };
    const s = styles[severity] || styles['Low'];
    return <span style={{ backgroundColor: s.bg, color: s.text, padding: '4px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: '600', display: 'inline-block' }}>{severity}</span>;
};

const MultiQueue = ({ label, sortKey, sortQueue, onSort }) => {
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
                <div style={{ color: '#333', fontSize: '13px' }}>{dep.version}</div><div><SeverityType severity={dep.vulns[0].severity} /></div><div style={{ color: '#333', fontSize: '13px' }}>{dep.vulns.length}</div><div style={{ color: '#333', fontSize: '13px' }}>-</div><div style={{ color: '#333', fontSize: '13px' }}>{dep.fixVersion}</div>
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
                            <MultiQueue label="CVE ID" sortKey="id" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="Severity" sortKey="severityWeight" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="Score" sortKey="score" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="Description" sortKey="description" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="Affected Versions" sortKey="affected" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="Fixed In" sortKey="fixedIn" sortQueue={cveSortQueue} onSort={handleCveSort} />
                            <MultiQueue label="CWE" sortKey="cwe" sortQueue={cveSortQueue} onSort={handleCveSort} />
                        </div>

                        {sortedCves.map((v, idx) => (
                            <div key={`${v.id}-${idx}-${Math.random()}`} style={{ display: 'grid', gridTemplateColumns: cveGridTemplate, alignItems: 'start', padding: '16px', borderBottom: '1px solid #f0f0f0', fontSize: '13px', color: '#161616' }}>
                                <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer" style={{ color: '#0f62fe', textDecoration: 'underline' }}>{v.id}</a><div><SeverityType severity={v.severity} /></div><div>{v.score !== '-' ? `${v.score}/10` : '-'}</div><div style={{ paddingRight: '20px', lineHeight: '1.4' }}>{v.description}</div><div>{v.affected}</div><div>{v.fixedIn}</div><div>{v.cwe}</div>
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
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <h2 style={{ margin: 0, fontSize: '20px', color: '#161616', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '12px' }}>
                        {repo.name}
                        <span style={{
                            fontSize: '11px', padding: '4px 8px', borderRadius: '12px',
                            backgroundColor: repo.dataSource.includes('Local') ? '#ffe5e5' : '#defbe6',
                            color: repo.dataSource.includes('Local') ? '#da1e28' : '#198038',
                            fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.5px'
                        }}>
                            {repo.dataSource}
                        </span>
                    </h2>
                    <SeverityType severity={repo.maxSeverity} />
                </div>
                <span style={{ fontSize: '16px', color: '#161616' }}>{isOpen ? '⌃' : '⌄'}</span>
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
                        <MultiQueue label="Dependency" sortKey="name" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <MultiQueue label="Version" sortKey="version" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <MultiQueue label="Severity" sortKey="maxScore" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <MultiQueue label="CVEs" sortKey="cves" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <MultiQueue label="Exploit" sortKey="exploit" sortQueue={depSortQueue} onSort={handleDepSort} />
                        <MultiQueue label="Fix Version" sortKey="fixVersion" sortQueue={depSortQueue} onSort={handleDepSort} />
                    </div>
                    {sortedDependencies.map(dep => <DependencyRow key={dep.name} dep={dep} />)}
                </div>
            )}
        </div>
    );
}

export default function App() {
    const [reports, setReports] = useState([]);
    const [token, setToken] = useState('');
    const envToken = import.meta.env.VITE_GITHUB_TOKEN || '';
    const [isLoading, setIsLoading] = useState(true);
    const [errorMsg, setErrorMsg] = useState('');
    const [fetchStatus, setFetchStatus] = useState(null);

    const fetchLocalData = async (repoName, fallbackJson) => {
        let data = null;
        let source = '';
        if (fallbackJson) {
            data = fallbackJson;
            source = 'Local Fallback (JSON)';
        } else {
            try {
                const localZipRes = await fetch('/test.zip');
                if (localZipRes.ok) {
                    const zipBlob = await localZipRes.blob();
                    const zip = await JSZip.loadAsync(zipBlob);
                    let jsonFile = Object.values(zip.files).find(f => !f.dir && f.name.includes(repoName) && f.name.endsWith('.json'));
                    if (!jsonFile) jsonFile = Object.values(zip.files).find(f => !f.dir && f.name.endsWith('.json') && !f.name.includes('package'));
                    if (jsonFile) {
                        data = JSON.parse(await jsonFile.async('string'));
                        source = 'Local Fallback (ZIP)';
                    }
                }
            } catch (e) {}
        }
        return { data, source };
    };

    const loadData = async (isFirstRun) => {
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
            let apiSuccessCount = 0;

            for (const repoConfig of reposToFetch) {
                let resultData = null;
                let resultSource = '';

                if (isFirstRun) {
                    const localRes = await fetchLocalData(repoConfig.name, repoConfig.fallback);
                    if (localRes.data) {
                        resultData = localRes.data;
                        resultSource = localRes.source;
                    } else {
                        const apiRes = await fetchLiveRepoData(repoConfig.name, token, envToken);
                        if (apiRes && apiRes.data) {
                            resultData = apiRes.data;
                            resultSource = `API: ${apiRes.extractMethod} (Key: ${apiRes.keyUsed})`;
                            apiSuccessCount++;
                        }
                    }
                } else {
                    const apiRes = await fetchLiveRepoData(repoConfig.name, token, envToken);
                    if (apiRes && apiRes.data) {
                        resultData = apiRes.data;
                        resultSource = `API: ${apiRes.extractMethod} (Key: ${apiRes.keyUsed})`;
                        apiSuccessCount++;
                    } else {
                        const localRes = await fetchLocalData(repoConfig.name, repoConfig.fallback);
                        if (localRes.data) {
                            resultData = localRes.data;
                            resultSource = localRes.source;
                        }
                    }
                }

                if (resultData) {
                    liveDataResults.push({ ...processRepo(resultData, repoConfig.name), dataSource: resultSource });
                }
            }

            liveDataResults.sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
            setReports(liveDataResults);

            if (apiSuccessCount === reposToFetch.length) setFetchStatus('live');
            else if (apiSuccessCount > 0) setFetchStatus('partial');
            else setFetchStatus('local');

        } catch (err) {
            setErrorMsg(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        loadData(true);
    }, []);

    const handleFetchLive = () => {
        loadData(false);
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
                    <button onClick={handleFetchLive} disabled={isLoading} style={{ padding: '10px 20px', backgroundColor: '#0f62fe', color: 'white', border: 'none', borderRadius: '4px', cursor: isLoading ? 'not-allowed' : 'pointer', fontWeight: '600', marginTop: '16px' }}>
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