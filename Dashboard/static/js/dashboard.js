/**
 * Canary Security Dashboard - Advanced TypeScript/React Frontend
 * ==============================================================
 * 
 * Modern, cloud-optimized dashboard JavaScript with TypeScript support,
 * React integration, and enterprise-grade functionality.
 * 
 * Features:
 * - React/TypeScript component integration
 * - Real-time WebSocket connections
 * - Advanced state management
 * - Cloud platform optimizations (AWS/Azure)
 * - Progressive Web App capabilities
 * - Advanced data visualization
 * - Enterprise security features
 */

interface Window {
  CanaryDashboard: typeof CanaryDashboard;
  React: any;
  ReactDOM: any;
}

// ===== TYPESCRIPT INTERFACES =====
interface ScanResult {
  id: number;
  repository_name: string;
  commit_hash: string;
  branch: string;
  timestamp: string;
  findings_count: number;
  critical_findings_count: number;
  status: 'completed' | 'running' | 'failed';
}

interface Finding {
  id: number;
  scan_id: number;
  file_path: string;
  line_number: number;
  rule_id: string;
  description: string;
  confidence: 'High' | 'Medium' | 'Low';
  status: 'New' | 'Acknowledged' | 'Resolved' | 'False Positive';
  secret_preview: string;
  created_at: string;
  updated_at: string;
}

interface DashboardMetrics {
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  resolved_findings: number;
  recent_activity: {
    scans_last_7_days: number;
    findings_last_7_days: number;
  };
  top_repositories: Array<{ name: string; findings: number }>;
}

interface AlertConfig {
  enabled: boolean;
  webhook_url: string;
  channel: string;
  threshold: string;
}

// ===== MAIN DASHBOARD CLASS =====
class CanaryDashboard {
  private config: {
    apiBaseUrl: string;
    wsUrl: string;
    refreshInterval: number;
    maxRetries: number;
    enablePWA: boolean;
    cloudProvider: 'aws' | 'azure' | 'gcp' | 'local';
  };
  
  private state: {
    isLoading: boolean;
    lastUpdate: Date | null;
    selectedFindings: Set<number>;
    currentUser: string | null;
    connectionStatus: 'connected' | 'connecting' | 'disconnected';
    darkMode: boolean;
  };
  
  private ws: WebSocket | null = null;
  private retryCount: number = 0;
  private updateInterval: number | null = null;
  private serviceWorker: ServiceWorker | null = null;

  constructor() {
    this.config = {
      apiBaseUrl: this.getApiBaseUrl(),
      wsUrl: this.getWebSocketUrl(),
      refreshInterval: 30000, // 30 seconds
      maxRetries: 3,
      enablePWA: true,
      cloudProvider: this.detectCloudProvider()
    };

    this.state = {
      isLoading: false,
      lastUpdate: null,
      selectedFindings: new Set(),
      currentUser: null,
      connectionStatus: 'disconnected',
      darkMode: this.getPreferredTheme() === 'dark'
    };

    this.init();
  }

  // ===== INITIALIZATION =====
  private async init(): Promise<void> {
    console.log('🚀 Initializing Canary Dashboard v3.0');
    
    try {
      await this.setupServiceWorker();
      await this.initializeReactComponents();
      await this.connectWebSocket();
      await this.loadInitialData();
      
      this.setupEventListeners();
      this.startPeriodicUpdates();
      this.setupKeyboardShortcuts();
      
      console.log('✅ Dashboard initialized successfully');
    } catch (error) {
      console.error('❌ Dashboard initialization failed:', error);
      this.showErrorNotification('Failed to initialize dashboard', error as Error);
    }
  }

  private getApiBaseUrl(): string {
    // Cloud-aware API URL detection
    const hostname = window.location.hostname;
    
    if (hostname.includes('amazonaws.com')) {
      return `https://${hostname}/api/v1`;
    } else if (hostname.includes('azurewebsites.net')) {
      return `https://${hostname}/api/v1`;
    } else if (hostname.includes('run.app')) {
      return `https://${hostname}/api/v1`;
    }
    
    return window.location.origin + '/api/v1';
  }

  private getWebSocketUrl(): string {
    const baseUrl = this.config.apiBaseUrl;
    return baseUrl.replace(/^http/, 'ws') + '/ws';
  }

  private detectCloudProvider(): 'aws' | 'azure' | 'gcp' | 'local' {
    const hostname = window.location.hostname;
    
    if (hostname.includes('amazonaws.com')) return 'aws';
    if (hostname.includes('azurewebsites.net')) return 'azure';
    if (hostname.includes('run.app')) return 'gcp';
    
    return 'local';
  }

  // ===== REACT COMPONENT INTEGRATION =====
  private async initializeReactComponents(): Promise<void> {
    if (typeof window.React === 'undefined') {
      console.warn('React not found, loading dynamically...');
      await this.loadReactLibraries();
    }

    // Initialize main React components
    const { createElement: h, useState, useEffect, useCallback } = window.React;
    const { createRoot } = window.ReactDOM;

    // Dashboard Metrics Component
    const DashboardMetrics = () => {
      const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
      const [loading, setLoading] = useState(true);

      const loadMetrics = useCallback(async () => {
        try {
          const data = await this.fetchMetrics();
          setMetrics(data);
        } catch (error) {
          console.error('Failed to load metrics:', error);
        } finally {
          setLoading(false);
        }
      }, []);

      useEffect(() => {
        loadMetrics();
        const interval = setInterval(loadMetrics, this.config.refreshInterval);
        return () => clearInterval(interval);
      }, [loadMetrics]);

      if (loading) {
        return h('div', { className: 'animate-pulse' }, 
          h('div', { className: 'grid grid-cols-1 md:grid-cols-4 gap-6' },
            ...Array(4).fill(null).map((_, i) => 
              h('div', { key: i, className: 'bg-gray-200 h-32 rounded-lg' })
            )
          )
        );
      }

      if (!metrics) {
        return h('div', { className: 'text-center py-8' },
          h('p', { className: 'text-gray-500' }, 'Failed to load metrics')
        );
      }

      return h('div', { className: 'grid grid-cols-1 md:grid-cols-4 gap-6' },
        h('div', { className: 'metric-card-info' },
          h('div', { className: 'metric-value text-blue-600' }, metrics.total_scans),
          h('div', { className: 'metric-label' }, 'Total Scans')
        ),
        h('div', { className: 'metric-card-critical' },
          h('div', { className: 'metric-value text-red-600' }, metrics.critical_findings),
          h('div', { className: 'metric-label' }, 'Critical Findings')
        ),
        h('div', { className: 'metric-card-success' },
          h('div', { className: 'metric-value text-green-600' }, metrics.resolved_findings),
          h('div', { className: 'metric-label' }, 'Resolved Findings')
        ),
        h('div', { className: 'metric-card-info' },
          h('div', { className: 'metric-value text-blue-600' }, 
            Math.round((metrics.resolved_findings / metrics.total_findings) * 100) || 0, '%'
          ),
          h('div', { className: 'metric-label' }, 'Resolution Rate')
        )
      );
    };

    // Mount React components
    const metricsContainer = document.getElementById('metrics-container');
    if (metricsContainer) {
      const root = createRoot(metricsContainer);
      root.render(h(DashboardMetrics));
    }
  }

  private async loadReactLibraries(): Promise<void> {
    const reactScript = document.createElement('script');
    reactScript.src = 'https://unpkg.com/react@18/umd/react.production.min.js';
    reactScript.crossOrigin = 'anonymous';
    
    const reactDomScript = document.createElement('script');
    reactDomScript.src = 'https://unpkg.com/react-dom@18/umd/react-dom.production.min.js';
    reactDomScript.crossOrigin = 'anonymous';

    document.head.appendChild(reactScript);
    document.head.appendChild(reactDomScript);

    return new Promise((resolve, reject) => {
      let loadedCount = 0;
      const onLoad = () => {
        loadedCount++;
        if (loadedCount === 2) resolve();
      };

      reactScript.onload = onLoad;
      reactDomScript.onload = onLoad;
      reactScript.onerror = reject;
      reactDomScript.onerror = reject;
    });
  }

  // ===== WEBSOCKET CONNECTION =====
  private async connectWebSocket(): Promise<void> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return;
    }

    this.state.connectionStatus = 'connecting';
    this.updateConnectionStatus();

    try {
      this.ws = new WebSocket(this.config.wsUrl);
      
      this.ws.onopen = () => {
        console.log('🔗 WebSocket connected');
        this.state.connectionStatus = 'connected';
        this.retryCount = 0;
        this.updateConnectionStatus();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.handleWebSocketMessage(data);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('🔌 WebSocket disconnected');
        this.state.connectionStatus = 'disconnected';
        this.updateConnectionStatus();
        this.scheduleReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.state.connectionStatus = 'disconnected';
        this.updateConnectionStatus();
      };

    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      this.state.connectionStatus = 'disconnected';
      this.updateConnectionStatus();
      this.scheduleReconnect();
    }
  }

  private handleWebSocketMessage(data: any): void {
    switch (data.type) {
      case 'new_scan':
        this.handleNewScan(data.payload);
        break;
      case 'critical_finding':
        this.handleCriticalFinding(data.payload);
        break;
      case 'metrics_update':
        this.handleMetricsUpdate(data.payload);
        break;
      case 'status_update':
        this.handleStatusUpdate(data.payload);
        break;
      default:
        console.warn('Unknown WebSocket message type:', data.type);
    }
  }

  private scheduleReconnect(): void {
    if (this.retryCount >= this.config.maxRetries) {
      console.error('Max WebSocket retry attempts reached');
      return;
    }

    const delay = Math.pow(2, this.retryCount) * 1000; // Exponential backoff
    this.retryCount++;
    
    setTimeout(() => {
      console.log(`🔄 Attempting WebSocket reconnect (${this.retryCount}/${this.config.maxRetries})`);
      this.connectWebSocket();
    }, delay);
  }

  // ===== DATA MANAGEMENT =====
  private async fetchMetrics(): Promise<DashboardMetrics> {
    const response = await this.apiCall('/metrics');
    return response;
  }

  private async fetchScans(limit: number = 50, offset: number = 0): Promise<ScanResult[]> {
    const response = await this.apiCall(`/scans?limit=${limit}&offset=${offset}`);
    return response.scans;
  }

  private async fetchFindings(filters: any = {}): Promise<Finding[]> {
    const params = new URLSearchParams(filters);
    const response = await this.apiCall(`/findings?${params}`);
    return response.findings;
  }

  private async updateFindingStatus(findingId: number, status: string, notes?: string): Promise<void> {
    await this.apiCall(`/findings/${findingId}/status`, {
      method: 'POST',
      body: JSON.stringify({ status, notes })
    });
  }

  private async apiCall(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = this.config.apiBaseUrl + endpoint;
    
    const defaultOptions: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      ...options
    };

    try {
      const response = await fetch(url, defaultOptions);
      
      if (!response.ok) {
        throw new Error(`API call failed: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API call failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // ===== EVENT HANDLERS =====
  private async loadInitialData(): Promise<void> {
    this.setLoading(true);
    
    try {
      await Promise.all([
        this.refreshMetrics(),
        this.refreshRecentScans(),
        this.refreshChartData()
      ]);
      
      this.state.lastUpdate = new Date();
    } finally {
      this.setLoading(false);
    }
  }

  private async refreshMetrics(): Promise<void> {
    try {
      const metrics = await this.fetchMetrics();
      this.updateMetricsDisplay(metrics);
    } catch (error) {
      console.error('Failed to refresh metrics:', error);
    }
  }

  private async refreshRecentScans(): Promise<void> {
    try {
      const scans = await this.fetchScans(10);
      this.updateRecentScansTable(scans);
    } catch (error) {
      console.error('Failed to refresh recent scans:', error);
    }
  }

  private async refreshChartData(): Promise<void> {
    try {
      const [trendsData, repoData] = await Promise.all([
        this.apiCall('/trends?days=30'),
        this.apiCall('/repository-stats')
      ]);
      
      this.updateCharts(trendsData, repoData);
    } catch (error) {
      console.error('Failed to refresh chart data:', error);
    }
  }

  private handleNewScan(scan: ScanResult): void {
    console.log('📊 New scan received:', scan);
    
    // Update metrics immediately
    this.refreshMetrics();
    
    // Show notification for critical findings
    if (scan.critical_findings_count > 0) {
      this.showNotification(
        'Critical Security Alert',
        `${scan.critical_findings_count} critical finding(s) in ${scan.repository_name}`,
        'error'
      );
    }
    
    // Update recent scans table
    this.refreshRecentScans();
  }

  private handleCriticalFinding(finding: Finding): void {
    console.log('🚨 Critical finding received:', finding);
    
    // Show immediate alert
    this.showCriticalAlert(finding);
    
    // Update findings list if visible
    if (document.getElementById('findings-container')) {
      this.refreshFindingsTable();
    }
  }

  private handleMetricsUpdate(metrics: DashboardMetrics): void {
    console.log('📈 Metrics updated:', metrics);
    this.updateMetricsDisplay(metrics);
  }

  private handleStatusUpdate(update: any): void {
    console.log('🔄 Status update received:', update);
    // Update relevant UI components based on status change
  }

  // ===== UI UPDATES =====
  private updateMetricsDisplay(metrics: DashboardMetrics): void {
    const elements = {
      'total-scans': metrics.total_scans,
      'total-findings': metrics.total_findings,
      'critical-findings': metrics.critical_findings,
      'resolved-findings': metrics.resolved_findings
    };

    Object.entries(elements).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) {
        this.animateValueChange(element, value);
      }
    });

    // Update resolution rate
    const resolutionRate = metrics.total_findings > 0 
      ? Math.round((metrics.resolved_findings / metrics.total_findings) * 100)
      : 0;
    
    const rateElement = document.getElementById('resolution-rate');
    if (rateElement) {
      this.animateValueChange(rateElement, resolutionRate + '%');
    }
  }

  private animateValueChange(element: HTMLElement, newValue: string | number): void {
    const currentValue = element.textContent || '0';
    const numericNew = typeof newValue === 'number' ? newValue : parseInt(newValue.toString());
    const numericCurrent = parseInt(currentValue);

    if (numericNew !== numericCurrent) {
      element.classList.add('animate-pulse');
      element.textContent = newValue.toString();
      
      setTimeout(() => {
        element.classList.remove('animate-pulse');
      }, 1000);
    }
  }

  private updateRecentScansTable(scans: ScanResult[]): void {
    const tbody = document.getElementById('recent-scans-tbody');
    if (!tbody) return;

    tbody.innerHTML = scans.map(scan => `
      <tr class="table-row ${scan.critical_findings_count > 0 ? 'table-row-critical' : ''}">
        <td class="table-cell">
          <div class="flex items-center">
            <svg class="w-4 h-4 mr-2 text-gray-500" fill="currentColor" viewBox="0 0 20 20">
              <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            ${scan.repository_name}
          </div>
        </td>
        <td class="table-cell">
          <span class="badge badge-secondary">${scan.branch}</span>
        </td>
        <td class="table-cell">
          <code class="text-xs">${scan.commit_hash.substring(0, 8)}</code>
        </td>
        <td class="table-cell text-gray-500">
          ${this.formatRelativeTime(new Date(scan.timestamp))}
        </td>
        <td class="table-cell">
          ${scan.findings_count > 0 
            ? `<span class="badge badge-warning">${scan.findings_count}</span>`
            : `<span class="badge badge-success">0</span>`
          }
        </td>
        <td class="table-cell">
          ${scan.critical_findings_count > 0
            ? `<span class="badge badge-critical">${scan.critical_findings_count}</span>`
            : '<span class="text-gray-400">-</span>'
          }
        </td>
        <td class="table-cell">
          <a href="/scans/${scan.id}" class="btn btn-sm btn-outline">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
            </svg>
            View
          </a>
        </td>
      </tr>
    `).join('');
  }

  private async refreshFindingsTable(): Promise<void> {
    // Implementation for findings table refresh
    const findings = await this.fetchFindings();
    // Update findings table UI
  }

  private updateCharts(trendsData: any, repoData: any): void {
    // Update Chart.js charts with new data
    if (window.Chart) {
      this.updateTrendsChart(trendsData);
      this.updateRepositoryChart(repoData);
    }
  }

  private updateTrendsChart(data: any): void {
    const ctx = document.getElementById('trends-chart') as HTMLCanvasElement;
    if (!ctx) return;

    if (ctx.chart) {
      ctx.chart.destroy();
    }

    ctx.chart = new (window as any).Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Findings Over Time',
          data: data.values,
          borderColor: '#3B82F6',
          backgroundColor: '#3B82F6',
          tension: 0.4,
          fill: false
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }

  private updateRepositoryChart(data: any): void {
    const ctx = document.getElementById('repository-chart') as HTMLCanvasElement;
    if (!ctx) return;

    if (ctx.chart) {
      ctx.chart.destroy();
    }

    ctx.chart = new (window as any).Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Findings by Repository',
          data: data.values,
          backgroundColor: [
            '#EF4444', '#F97316', '#EAB308', '#22C55E', 
            '#3B82F6', '#8B5CF6', '#EC4899', '#06B6D4'
          ]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }

  // ===== NOTIFICATIONS =====
  private showNotification(title: string, message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info', duration: number = 5000): void {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} fixed top-4 right-4 z-50 max-w-sm animate-slide-in`;
    notification.innerHTML = `
      <div class="flex items-start">
        <div class="flex-shrink-0">
          ${this.getNotificationIcon(type)}
        </div>
        <div class="ml-3 w-0 flex-1">
          <p class="text-sm font-medium">${title}</p>
          <p class="mt-1 text-sm">${message}</p>
        </div>
        <div class="ml-4 flex-shrink-0 flex">
          <button class="inline-flex text-gray-400 hover:text-gray-600" onclick="this.parentElement.parentElement.parentElement.remove()">
            <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
            </svg>
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after duration
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, duration);

    // Trigger browser notification if permitted
    if (this.canShowBrowserNotifications() && (type === 'error' || type === 'warning')) {
      new Notification(title, {
        body: message,
        icon: '/static/images/canary-icon.png'
      });
    }
  }

  private showCriticalAlert(finding: Finding): void {
    const modal = document.createElement('div');
    modal.className = 'modal-backdrop';
    modal.innerHTML = `
      <div class="modal">
        <div class="modal-container">
          <div class="modal-content">
            <div class="modal-header bg-red-600 text-white">
              <h3 class="text-lg font-semibold">🚨 Critical Security Alert</h3>
            </div>
            <div class="modal-body">
              <div class="space-y-4">
                <div>
                  <h4 class="font-semibold text-red-800">Critical secret detected:</h4>
                  <p class="text-gray-700">${finding.description}</p>
                </div>
                <div class="bg-gray-50 p-3 rounded">
                  <p><strong>File:</strong> <code>${finding.file_path}:${finding.line_number}</code></p>
                  <p><strong>Rule:</strong> ${finding.rule_id}</p>
                  <p><strong>Preview:</strong> <code class="text-red-600">${finding.secret_preview}</code></p>
                </div>
                <div class="bg-yellow-50 border border-yellow-200 p-3 rounded">
                  <h5 class="font-semibold text-yellow-800">⚡ Immediate Action Required:</h5>
                  <ul class="mt-2 text-sm text-yellow-700 list-disc list-inside">
                    <li>🛑 DO NOT MERGE this code</li>
                    <li>🔄 Rotate the exposed credential immediately</li>
                    <li>🗑️ Remove the secret from source code</li>
                    <li>🔐 Use environment variables or secure vaults</li>
                  </ul>
                </div>
              </div>
            </div>
            <div class="modal-footer">
              <button class="btn btn-primary" onclick="this.closest('.modal-backdrop').remove()">
                Acknowledge
              </button>
              <a href="/scans/${finding.scan_id}" class="btn btn-outline">
                View Full Report
              </a>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
  }

  private getNotificationIcon(type: string): string {
    const icons = {
      success: '<svg class="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
      error: '<svg class="h-6 w-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>',
      warning: '<svg class="h-6 w-6 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>',
      info: '<svg class="h-6 w-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
    };
    return icons[type] || icons.info;
  }

  private canShowBrowserNotifications(): boolean {
    return 'Notification' in window && Notification.permission === 'granted';
  }

  // ===== UTILITY METHODS =====
  private formatRelativeTime(date: Date): string {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const diffInMinutes = Math.floor(diff / 60000);

    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  }

  private getPreferredTheme(): 'light' | 'dark' {
    const stored = localStorage.getItem('canary-theme');
    if (stored) return stored as 'light' | 'dark';
    
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  private setLoading(loading: boolean): void {
    this.state.isLoading = loading;
    
    const loadingElements = document.querySelectorAll('.loading-target');
    loadingElements.forEach(element => {
      if (loading) {
        element.classList.add('loading');
      } else {
        element.classList.remove('loading');
      }
    });

    document.body.style.cursor = loading ? 'wait' : 'default';
  }

  private updateConnectionStatus(): void {
    const indicator = document.getElementById('connection-status');
    if (!indicator) return;

    const statusMap = {
      connected: { class: 'text-green-500', text: 'Connected', icon: '🟢' },
      connecting: { class: 'text-yellow-500', text: 'Connecting...', icon: '🟡' },
      disconnected: { class: 'text-red-500', text: 'Disconnected', icon: '🔴' }
    };

    const status = statusMap[this.state.connectionStatus];
    indicator.className = `flex items-center space-x-1 text-sm ${status.class}`;
    indicator.innerHTML = `<span>${status.icon}</span><span>${status.text}</span>`;
  }

  private setupEventListeners(): void {
    // Theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => this.toggleTheme());
    }

    // Window focus/blur for connection management
    window.addEventListener('focus', () => {
      if (this.state.connectionStatus === 'disconnected') {
        this.connectWebSocket();
      }
    });

    window.addEventListener('beforeunload', () => {
      if (this.ws) {
        this.ws.close();
      }
    });

    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }

  private setupKeyboardShortcuts(): void {
    document.addEventListener('keydown', (event) => {
      // Ctrl/Cmd + R: Refresh data
      if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
        event.preventDefault();
        this.refreshAllData();
      }

      // Escape: Clear selections
      if (event.key === 'Escape') {
        this.clearAllSelections();
      }

      // Ctrl/Cmd + K: Search
      if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        this.focusSearch();
      }
    });
  }

  private toggleTheme(): void {
    this.state.darkMode = !this.state.darkMode;
    const theme = this.state.darkMode ? 'dark' : 'light';
    
    document.documentElement.classList.toggle('dark', this.state.darkMode);
    localStorage.setItem('canary-theme', theme);
  }

  private startPeriodicUpdates(): void {
    this.updateInterval = window.setInterval(() => {
      if (!document.hidden && this.state.connectionStatus === 'connected') {
        this.refreshMetrics();
      }
    }, this.config.refreshInterval);
  }

  private async refreshAllData(): Promise<void> {
    this.showNotification('Refreshing Data', 'Updating all dashboard information...', 'info', 2000);
    await this.loadInitialData();
  }

  private clearAllSelections(): void {
    this.state.selectedFindings.clear();
    
    const checkboxes = document.querySelectorAll('input[type="checkbox"]:checked');
    checkboxes.forEach((cb: HTMLInputElement) => {
      cb.checked = false;
    });
  }

  private focusSearch(): void {
    const searchInput = document.getElementById('global-search') as HTMLInputElement;
    if (searchInput) {
      searchInput.focus();
    }
  }

  // ===== SERVICE WORKER SETUP =====
  private async setupServiceWorker(): Promise<void> {
    if (!this.config.enablePWA || !('serviceWorker' in navigator)) {
      return;
    }

    try {
      const registration = await navigator.serviceWorker.register('/sw.js');
      console.log('✅ Service Worker registered:', registration.scope);
      this.serviceWorker = registration.active;
    } catch (error) {
      console.warn('Service Worker registration failed:', error);
    }
  }

  // ===== PUBLIC API =====
  public async exportData(format: 'json' | 'csv' = 'json'): Promise<void> {
    try {
      const response = await this.apiCall(`/export?format=${format}`);
      const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `canary-export-${new Date().toISOString().split('T')[0]}.${format}`;
      a.click();
      
      URL.revokeObjectURL(url);
    } catch (error) {
      this.showNotification('Export Failed', 'Failed to export data', 'error');
    }
  }

  public async testSlackIntegration(): Promise<void> {
    try {
      await this.apiCall('/test-alert', { method: 'POST' });
      this.showNotification('Slack Test', 'Test alert sent successfully', 'success');
    } catch (error) {
      this.showNotification('Slack Test Failed', 'Failed to send test alert', 'error');
    }
  }

  public getState(): typeof this.state {
    return { ...this.state };
  }

  public getConfig(): typeof this.config {
    return { ...this.config };
  }

  // Cleanup method
  public destroy(): void {
    if (this.ws) {
      this.ws.close();
    }
    
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
    }
    
    console.log('🔄 Dashboard destroyed');
  }
}

// ===== GLOBAL INITIALIZATION =====
declare global {
  interface HTMLCanvasElement {
    chart?: any;
  }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.CanaryDashboard = new CanaryDashboard();
  console.log('🎉 Canary Security Dashboard loaded successfully');
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CanaryDashboard;
}

// AMD support
if (typeof define === 'function' && define.amd) {
  define([], () => CanaryDashboard);
}