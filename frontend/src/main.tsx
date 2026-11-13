import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import LandingPage from './pages/LandingPage'
import ScanConfigPage from './pages/ScanConfigPage'
import SecurityDashboardPage from './pages/SecurityDashboardPage'
import VulnerabilitiesPage from './pages/VulnerabilitiesPage'
import ProcessGraphPage from './pages/ProcessGraphPage'
import MaliciousAnalysisPage from './pages/MaliciousAnalysisPage'
import TamperabilityPage from './pages/TamperabilityPage'
import ReportsPage from './pages/ReportsPage'
import ScanHistoryPage from './pages/ScanHistoryPage'
import TelemetryPage from './pages/TelemetryPage'
import ExploitGraphPage from './pages/exploit-graph'
import SecurityDebtPage from './pages/SecurityDebtPage'
import DualAIRemediationPage from './pages/DualAIRemediationPage'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/scan-history" element={<ScanHistoryPage />} />
        <Route path="/telemetry" element={<TelemetryPage />} />
        <Route path="/scan" element={<ScanConfigPage />} />
        <Route path="/dashboard/:scanId/security-debt" element={<SecurityDebtPage />} />
        <Route path="/dashboard/:scanId/dual-ai-remediation" element={<DualAIRemediationPage />} />
        <Route path="/dashboard/:scanId/vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="/dashboard/:scanId/process-graph" element={<ProcessGraphPage />} />
        <Route path="/dashboard/:scanId/malicious" element={<MaliciousAnalysisPage />} />
        <Route path="/dashboard/:scanId/tamperability" element={<TamperabilityPage />} />
        <Route path="/dashboard/:scanId/reports" element={<ReportsPage />} />
        <Route path="/dashboard/:scanId/exploit-graph" element={<ExploitGraphPage />} />
        <Route path="/dashboard/:scanId" element={<SecurityDashboardPage />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
