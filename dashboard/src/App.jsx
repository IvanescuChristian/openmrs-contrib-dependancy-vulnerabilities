import React, { useState, useMemo } from 'react';
import JSZip from 'jszip'; // <--- Importăm librăria de dezarhivare
// Fallback pentru Phase 1 (Date statice)
import billingData from './data/openmrs-module-billing.json';
import coreData from './data/openmrs-core.json';
import idgenData from './data/openmrs-module-idgen.json';

// --- UTILS & CORE LOGIC ---
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

        const rawScore = v.cvssScore || v.score || (SEVERITY_WEIGHT[v.severity] * 2.5);
        const severityWeight = SEVERITY_WEIGHT[v.severity] || 0;

        if (rawScore > acc[pkgName].maxScore) acc[pkgName].maxScore = rawScore;

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

// --- API GITHUB LOGIC (PHASE 2) ---
async function fetchLiveRepoData(repoName, token) {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
        // 1. Luăm ultima rulare reușită de pe main
        const runsRes = await fetch(`https://api.github.com/repos/openmrs/${repoName}/actions/runs?branch=main&status=success`, { headers });
        if (!runsRes.ok) throw new Error('Nu am putut obține rulările. (Verifică token-ul)');
        const runsData = await runsRes.json();

        if (!runsData.workflow_runs || runsData.workflow_runs.length === 0) return null;
        const latestRun = runsData.workflow_runs[0];

        // 2. Căutăm artifactele pentru rularea respectivă
        const artifactsRes = await fetch(latestRun.artifacts_url, { headers });
        const artifactsData = await artifactsRes.json();

        const reportArtifact = artifactsData.artifacts.find(a =>
            a.name.toLowerCase().includes('report') || a.name.toLowerCase().includes('dependency')
        );
        if (!reportArtifact) return null;

        // 3. Descărcăm ZIP-ul
        const zipRes = await fetch(reportArtifact.archive_download_url, { headers });
        if (!zipRes.ok) throw new Error('Eroare la descărcarea arhivei. Ai nevoie de un Token.');
        const zipBlob = await zipRes.blob();

        // 4. Dezarhivăm și citim JSON-ul în memorie
        const zip = await JSZip.loadAsync(zipBlob);
        const jsonFile = Object.values(zip.files).find(f => f.name.endsWith('.json'));
        if (!jsonFile) return null;

        const jsonString = await jsonFile.async('string');
        return JSON.parse(jsonString);
    } catch (error) {
        console.error(`Eroare la ${repoName}:`, error);
        throw error;
    }
}

// --- COMPONENTE STILIZATE ---
const SeverityPill = ({ severity }) => { /* ... codul tău vechi (rămâne la fel) ... */
    if (!severity || severity === '-' || severity === 'None') return null;
    const styles = { 'Critical': { bg: '#ff8a8a', text: '#5a0000' }, 'High': { bg: '#ffc6c6', text: '#7a0000' }, 'Medium': { bg: '#ffe58f', text: '#5c4300' }, 'Low': { bg: '#d6e4ff', text: '#002c8c' } };
    const s = styles[severity] || styles['Low'];
    return <span style={{ backgroundColor: s.bg, color: s.text, padding: '4px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: '600', display: 'inline-block' }}>{severity}</span>;
};

const SortableHeader = ({ label, sortKey, currentSortKey, sortOrder, onSort }) => { /* ... codul tău vechi ... */
    const isActive = currentSortKey === sortKey;
    return (
        <div onClick={() => onSort(sortKey)} style={{ display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer', userSelect: 'none', color: isActive ? '#0f62fe' : '#161616', fontWeight: '600' }}>
            {label} <span style={{ fontSize: '10px', color: isActive ? '#0f62fe' : '#a8a8a8' }}>{isActive ? (sortOrder === 'desc' ? '▼' : '▲') : '↕'}</span>
        </div>
    );
};

const depGridTemplate = "3fr 1.5fr 1.5fr 1fr 1fr 1.5fr";
const cveGridTemplate = "1.5fr 1fr 1fr 3fr 1.5fr 1fr 1fr";

function DependencyRow({ dep }) { /* ... codul tău vechi ... */
    const [isOpen, setIsOpen] = useState(false);
    const [cveSort, setCveSort] = useState({ key: 'severityWeight', order: 'desc' });
    const handleCveSort = (key) => setCveSort(prev => ({ key, order: prev.key === key && prev.order === 'desc' ? 'asc' : 'desc' }));
    const sortedCves = useMemo(() => {
        return [...dep.vulns].sort((a, b) => {
            let valA = a[cveSort.key], valB = b[cveSort.key];
            if (valA === '-') valA = ''; if (valB === '-') valB = '';
            if (typeof valA === 'number' && typeof valB === 'number') return cveSort.order === 'desc' ? valB - valA : valA - valB;
            const cmp = String(valA).localeCompare(String(valB), undefined, { numeric: true });
            return cveSort.order === 'desc' ? -cmp : cmp;
        });
    }, [dep.vulns, cveSort]);

    return (
        <div style={{ borderBottom: '1px solid #e0e0e0' }}>
            <div onClick={() => setIsOpen(!isOpen)} style={{ display: 'grid', gridTemplateColumns: depGridTemplate, alignItems: 'center', padding: '16px 24px', cursor: 'pointer', backgroundColor: isOpen ? '#fcfcfc' : '#fff', transition: 'background 0.2s' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}><span style={{ color: '#161616', fontSize: '12px', width: '16px' }}>{isOpen ? '⌃' : '⌄'}</span><span style={{ color: '#161616', fontSize: '14px', fontWeight: isOpen ? '600' : '400' }}>{dep.name}</span></div>
                <div style={{ color: '#333', fontSize: '13px' }}>{dep.version}</div><div><SeverityPill severity={dep.vulns[0].severity} /></div><div style={{ color: '#333', fontSize: '13px' }}>{dep.vulns.length}</div><div style={{ color: '#333', fontSize: '13px' }}>-</div><div style={{ color: '#333', fontSize: '13px' }}>{dep.fixVersion}</div>
            </div>
            {isOpen && (
                <div style={{ padding: '0 24px 24px 60px', backgroundColor: '#fcfcfc' }}>
                    <div style={{ border: '1px solid #e0e0e0', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: cveGridTemplate, backgroundColor: '#f4f4f4', padding: '12px 16px', borderBottom: '1px solid #e0e0e0', fontSize: '13px' }}>
                            <SortableHeader label="CVE ID" sortKey="id" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="Severity" sortKey="severityWeight" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="Score" sortKey="score" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="Description" sortKey="description" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="Affected Versions" sortKey="affected" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="Fixed In" sortKey="fixedIn" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} /><SortableHeader label="CWE" sortKey="cwe" currentSortKey={cveSort.key} sortOrder={cveSort.order} onSort={handleCveSort} />
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

function RepoAccordion({ repo }) { /* ... codul tău vechi ... */
    const [isOpen, setIsOpen] = useState(true);
    const [depSort, setDepSort] = useState({ key: 'maxScore', order: 'desc' });
    const handleDepSort = (key) => setDepSort(prev => ({ key, order: prev.key === key && prev.order === 'desc' ? 'asc' : 'desc' }));
    const sortedDependencies = useMemo(() => {
        return [...repo.dependencies].sort((a, b) => {
            let valA = a[depSort.key], valB = b[depSort.key];
            if (depSort.key === 'cves') { valA = a.vulns.length; valB = b.vulns.length; }
            if (valA === '-') valA = ''; if (valB === '-') valB = '';
            if (typeof valA === 'number' && typeof valB === 'number') return depSort.order === 'desc' ? valB - valA : valA - valB;
            const cmp = String(valA).localeCompare(String(valB), undefined, { numeric: true });
            return depSort.order === 'desc' ? -cmp : cmp;
        });
    }, [repo.dependencies, depSort]);

    return (
        <div style={{ backgroundColor: 'white', border: '1px solid #e0e0e0', marginBottom: '24px' }}>
            <div onClick={() => setIsOpen(!isOpen)} style={{ padding: '24px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: isOpen ? '1px solid #e0e0e0' : 'none' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}><h2 style={{ margin: 0, fontSize: '20px', color: '#161616', fontWeight: '600' }}>{repo.name}</h2><SeverityPill severity={repo.maxSeverity} /></div><span style={{ fontSize: '16px', color: '#161616' }}>{isOpen ? '⌃' : '⌄'}</span>
            </div>
            {isOpen && (
                <div>
                    <div style={{ display: 'grid', gridTemplateColumns: depGridTemplate, backgroundColor: '#e0e0e0', padding: '16px 24px', fontSize: '14px' }}>
                        <SortableHeader label="Dependency" sortKey="name" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} /><SortableHeader label="Version" sortKey="version" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} /><SortableHeader label="Severity" sortKey="maxScore" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} /><SortableHeader label="CVEs" sortKey="cves" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} /><SortableHeader label="Exploit" sortKey="exploit" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} /><SortableHeader label="Fix Version" sortKey="fixVersion" currentSortKey={depSort.key} sortOrder={depSort.order} onSort={handleDepSort} />
                    </div>
                    {sortedDependencies.map(dep => <DependencyRow key={dep.name} dep={dep} />)}
                </div>
            )}
        </div>
    );
}

// --- NIVELUL 1: Aplicația Principală ---
export default function App() {
    // Phase 1 (Date statice) ca default
    const staticReports = useMemo(() => {
        return [
            processRepo(coreData, 'openmrs-core'),
            processRepo(idgenData, 'openmrs-module-idgen'),
            processRepo(billingData, 'openmrs-module-billing')
        ].sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
    }, []);

    const [reports, setReports] = useState(staticReports);
    const [token, setToken] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');
    const [isLive, setIsLive] = useState(false); // Să știm dacă afișăm date statice sau live

    // Funcția apelată când apeși "Fetch Live Data"
    const handleFetchLive = async () => {
        setIsLoading(true);
        setErrorMsg('');

        try {
            const reposToFetch = ['openmrs-core', 'openmrs-module-idgen', 'openmrs-module-billing'];
            const liveDataResults = [];

            for (const repo of reposToFetch) {
                const rawJson = await fetchLiveRepoData(repo, token);
                if (rawJson) {
                    liveDataResults.push(processRepo(rawJson, repo));
                }
            }

            if (liveDataResults.length === 0) {
                throw new Error("Nu am putut obține date live. Verifică dacă token-ul este corect.");
            }

            // Sortăm și setăm datele noi
            liveDataResults.sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));
            setReports(liveDataResults);
            setIsLive(true);
        } catch (err) {
            setErrorMsg(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div style={{ backgroundColor: '#fafafa', minHeight: '100vh', padding: '40px 20px', fontFamily: '"Inter", "Segoe UI", sans-serif' }}>
            <div style={{ maxWidth: '1400px', margin: '0 auto', width: '100%' }}>

                <header style={{ marginBottom: '40px' }}>
                    <h1 style={{ fontSize: '42px', color: '#161616', margin: '0 0 16px 0', fontWeight: '400', letterSpacing: '-0.5px' }}>
                        OpenMRS Dependency Vulnerability Report
                    </h1>
                    <div style={{ height: '6px', width: '80px', backgroundColor: '#008577', marginBottom: '24px' }}></div>
                    <p style={{ color: '#333', fontSize: '16px', maxWidth: '1200px', lineHeight: '1.5' }}>
                        A summary of known security vulnerabilities detected across OpenMRS modules by automated dependency scanning.
                        Each module lists its vulnerable dependencies, severity levels, and recommended fix versions.
                    </p>
                </header>

                {/* --- SECȚIUNEA PHASE 2 (CONTROALE API) --- */}
                <div style={{ backgroundColor: '#fff', padding: '20px', borderRadius: '4px', border: '1px solid #dcdcdc', marginBottom: '32px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, maxWidth: '400px' }}>
                        <label style={{ fontSize: '12px', fontWeight: '600', color: '#666' }}>GitHub Personal Access Token (Opțional pentru statice, Necesar pt live):</label>
                        <input
                            type="password"
                            value={token}
                            onChange={(e) => setToken(e.target.value)}
                            placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                            style={{ padding: '8px 12px', borderRadius: '4px', border: '1px solid #ccc' }}
                        />
                    </div>
                    <button
                        onClick={handleFetchLive}
                        disabled={isLoading || !token}
                        style={{
                            padding: '10px 20px', backgroundColor: token ? '#0f62fe' : '#e0e0e0', color: token ? 'white' : '#888',
                            border: 'none', borderRadius: '4px', cursor: token && !isLoading ? 'pointer' : 'not-allowed', fontWeight: '600',
                            marginTop: '16px'
                        }}
                    >
                        {isLoading ? '⏳ Se descarcă...' : 'Fetch Live Data (Phase 2)'}
                    </button>

                    {isLive && !isLoading && <span style={{ marginTop: '16px', color: '#24a148', fontWeight: 'bold' }}>✅ Date Live Încărcate</span>}
                    {!isLive && !isLoading && <span style={{ marginTop: '16px', color: '#f1c21b', fontWeight: 'bold' }}>⚠️ Date Statice (Phase 1)</span>}
                </div>

                {errorMsg && (
                    <div style={{ backgroundColor: '#ffe5e5', color: '#da1e28', padding: '16px', borderRadius: '4px', marginBottom: '24px', borderLeft: '4px solid #da1e28' }}>
                        <strong>Eroare:</strong> {errorMsg}
                    </div>
                )}

                {/* Randăm rapoartele (Fie statice, fie live, depinde ce s-a încărcat) */}
                {isLoading ? (
                    <div style={{ textAlign: 'center', padding: '50px', fontSize: '18px', color: '#666' }}>
                        Se descarcă și se dezarhivează rapoartele din GitHub Actions. Te rugăm să aștepți...
                    </div>
                ) : (
                    reports.map(repo => <RepoAccordion key={repo.name} repo={repo} />)
                )}

            </div>
        </div>
    );
}