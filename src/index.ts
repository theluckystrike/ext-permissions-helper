/**
 * Permissions Helper for Chrome Extensions
 * Comprehensive permissions management with request handling, preflight checks, and user consent tracking
 */

export type PermissionType = 'host' | 'api';
export type PermissionStatus = 'granted' | 'denied' | 'prompt' | 'unknown';

export interface Permission {
  type: PermissionType;
  value: string;
  description?: string;
}

export interface PermissionRequest {
  permissions: Permission[];
  rationale?: string;
  context?: Record<string, any>;
  timestamp: number;
  id: string;
}

export interface PermissionResult {
  granted: string[];
  denied: string[];
  pending: string[];
}

export interface PermissionHistoryEntry {
  id: string;
  permission: string;
  action: 'granted' | 'denied' | 'revoked' | 'requested';
  timestamp: number;
  context?: Record<string, any>;
}

export interface PermissionConfig {
  required: Permission[];
  optional: Permission[];
  rationale?: Record<string, string>;
  autoRequest?: boolean;
  persistent?: boolean;
}

/**
 * Main Permissions Manager
 */
export class PermissionsManager {
  private requiredPermissions: Set<string> = new Set();
  private optionalPermissions: Set<string> = new Set();
  private history: PermissionHistoryEntry[] = [];
  private listeners: Set<(entry: PermissionHistoryEntry) => void> = new Set();
  private maxHistory: number = 100;

  constructor(config?: PermissionConfig) {
    if (config) {
      this.loadConfig(config);
    }
  }

  /**
   * Load permission configuration
   */
  loadConfig(config: PermissionConfig): void {
    // Load required permissions
    for (const perm of config.required) {
      const permString = this.formatPermission(perm);
      this.requiredPermissions.add(permString);
    }

    // Load optional permissions
    for (const perm of config.optional) {
      const permString = this.formatPermission(perm);
      this.optionalPermissions.add(permString);
    }
  }

  /**
   * Check current permission status
   */
  async checkPermissions(): Promise<Record<string, PermissionStatus>> {
    try {
      const result = await chrome.permissions.getAll();
      const permissions = result.permissions || [];
      const origins = result.origins || [];

      const status: Record<string, PermissionStatus> = {};

      // Check required permissions
      for (const perm of this.requiredPermissions) {
        if (this.isHostPermission(perm)) {
          status[perm] = origins.includes(perm) ? 'granted' : 'denied';
        } else {
          status[perm] = permissions.includes(perm) ? 'granted' : 'denied';
        }
      }

      // Check optional permissions
      for (const perm of this.optionalPermissions) {
        if (this.isHostPermission(perm)) {
          status[perm] = origins.includes(perm) ? 'granted' : 'prompt';
        } else {
          status[perm] = permissions.includes(perm) ? 'granted' : 'prompt';
        }
      }

      return status;
    } catch (error) {
      console.error('[PermissionsManager] Check error:', error);
      return {};
    }
  }

  /**
   * Check if specific permission is granted
   */
  async isGranted(permission: string): Promise<boolean> {
    try {
      return await chrome.permissions.contains({
        permissions: [permission],
        origins: this.isHostPermission(permission) ? [permission] : []
      });
    } catch {
      return false;
    }
  }

  /**
   * Check if all required permissions are granted
   */
  async hasAllRequired(): Promise<boolean> {
    const status = await this.checkPermissions();
    
    for (const perm of this.requiredPermissions) {
      if (status[perm] !== 'granted') {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Check if any required permissions are missing
   */
  async getMissingPermissions(): Promise<string[]> {
    const status = await this.checkPermissions();
    const missing: string[] = [];

    for (const perm of this.requiredPermissions) {
      if (status[perm] !== 'granted') {
        missing.push(perm);
      }
    }

    return missing;
  }

  /**
   * Request permissions from user
   */
  async requestPermissions(
    permissions: string[],
    rationale?: string
  ): Promise<PermissionResult> {
    const result: PermissionResult = {
      granted: [],
      denied: [],
      pending: []
    };

    // Check which permissions need to be requested
    for (const perm of permissions) {
      const alreadyGranted = await this.isGranted(perm);
      
      if (alreadyGranted) {
        result.granted.push(perm);
        this.addHistory(perm, 'granted');
      } else {
        result.pending.push(perm);
      }
    }

    // Request pending permissions
    if (result.pending.length > 0) {
      try {
        const granted = await chrome.permissions.request({
          permissions: result.pending.filter(p => !this.isHostPermission(p)),
          origins: result.pending.filter(p => this.isHostPermission(p))
        });

        if (granted) {
          result.granted.push(...result.pending);
          result.pending = [];
          
          for (const perm of result.granted) {
            this.addHistory(perm, 'granted', { rationale });
          }
        } else {
          result.denied.push(...result.pending);
          result.pending = [];
          
          for (const perm of result.denied) {
            this.addHistory(perm, 'denied', { rationale });
          }
        }
      } catch (error) {
        console.error('[PermissionsManager] Request error:', error);
        result.denied.push(...result.pending);
        result.pending = [];
      }
    }

    return result;
  }

  /**
   * Request required permissions with rationale
   */
  async requestRequired(): Promise<PermissionResult> {
    const rationaleMap = this.getRationaleMap();
    return this.requestPermissions(
      Array.from(this.requiredPermissions),
      rationaleMap['*']
    );
  }

  /**
   * Request optional permissions
   */
  async requestOptional(): Promise<PermissionResult> {
    return this.requestPermissions(Array.from(this.optionalPermissions));
  }

  /**
   * Revoke a permission
   */
  async revokePermission(permission: string): Promise<boolean> {
    try {
      const removed = await chrome.permissions.remove({
        permissions: [permission],
        origins: this.isHostPermission(permission) ? [permission] : []
      });

      if (removed) {
        this.addHistory(permission, 'revoked');
      }

      return removed;
    } catch (error) {
      console.error('[PermissionsManager] Revoke error:', error);
      return false;
    }
  }

  /**
   * Preflight check - test if permission can be granted without prompting
   */
  async preflightCheck(permission: string): Promise<{
    canRequest: boolean;
    reason?: string;
  }> {
    // Check if already granted
    if (await this.isGranted(permission)) {
      return { canRequest: true };
    }

    // Check if it's a required permission
    if (this.requiredPermissions.has(permission)) {
      return { canRequest: true };
    }

    // Check manifest permissions
    const manifest = chrome.runtime.getManifest();
    const allPerms = [...(manifest.permissions || []), ...(manifest.optional_permissions || [])];
    
    if (!allPerms.includes(permission)) {
      return { 
        canRequest: false, 
        reason: 'Permission not declared in manifest' 
      };
    }

    return { canRequest: true };
  }

  /**
   * Get permission details
   */
  getPermissionDetails(permission: string): {
    type: PermissionType;
    value: string;
    description: string;
    isRequired: boolean;
    isOptional: boolean;
  } {
    const isHost = this.isHostPermission(permission);
    
    return {
      type: isHost ? 'host' : 'api',
      value: permission,
      description: this.getPermissionDescription(permission),
      isRequired: this.requiredPermissions.has(permission),
      isOptional: this.optionalPermissions.has(permission)
    };
  }

  /**
   * Get all declared permissions
   */
  getDeclaredPermissions(): {
    required: string[];
    optional: string[];
  } {
    return {
      required: Array.from(this.requiredPermissions),
      optional: Array.from(this.optionalPermissions)
    };
  }

  /**
   * Get permission history
   */
  getHistory(filter?: {
    permission?: string;
    action?: string;
    since?: number;
    limit?: number;
  }): PermissionHistoryEntry[] {
    let history = [...this.history];

    if (filter) {
      if (filter.permission) {
        history = history.filter(h => h.permission === filter.permission);
      }
      if (filter.action) {
        history = history.filter(h => h.action === filter.action);
      }
      if (filter.since) {
        history = history.filter(h => h.timestamp >= filter.since);
      }
    }

    return history
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, filter?.limit || this.maxHistory);
  }

  /**
   * Clear permission history
   */
  clearHistory(): void {
    this.history = [];
  }

  /**
   * Listen to permission changes
   */
  onPermissionChange(callback: (entry: PermissionHistoryEntry) => void): () => void {
    // Listen to Chrome's permission onRemoved
    const removedListener = (permissions: chrome.permissions.Permissions) => {
      if (permissions.permissions) {
        for (const perm of permissions.permissions) {
          this.addHistory(perm, 'revoked');
        }
      }
      if (permissions.origins) {
        for (const origin of permissions.origins) {
          this.addHistory(origin, 'revoked');
        }
      }
    };

    chrome.permissions.onRemoved.addListener(removedListener);
    this.listeners.add(callback);

    return () => {
      chrome.permissions.onRemoved.removeListener(removedListener);
      this.listeners.delete(callback);
    };
  }

  /**
   * Add history entry
   */
  private addHistory(
    permission: string, 
    action: 'granted' | 'denied' | 'revoked' | 'requested',
    context?: Record<string, any>
  ): void {
    const entry: PermissionHistoryEntry = {
      id: this.generateId(),
      permission,
      action,
      timestamp: Date.now(),
      context
    };

    this.history.unshift(entry);

    // Trim history if needed
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(0, this.maxHistory);
    }

    // Notify listeners
    this.listeners.forEach(listener => listener(entry));
  }

  /**
   * Format permission to string
   */
  private formatPermission(permission: Permission): string {
    if (permission.type === 'host') {
      return permission.value;
    }
    return permission.value;
  }

  /**
   * Check if permission is a host permission
   */
  private isHostPermission(permission: string): boolean {
    return permission.includes('://') || permission.startsWith('*://');
  }

  /**
   * Get permission description
   */
  private getPermissionDescription(permission: string): string {
    const descriptions: Record<string, string> = {
      'tabs': 'Access browser tabs and navigation',
      'activeTab': 'Access the active tab when you click',
      'storage': 'Store data locally',
      'cookies': 'Read and modify cookies',
      'webRequest': 'Intercept and modify network requests',
      'webRequestBlocking': 'Block network requests',
      'notifications': 'Display desktop notifications',
      'clipboardRead': 'Read from clipboard',
      'clipboardWrite': 'Write to clipboard',
      'geolocation': 'Access user location',
      'bookmarks': 'Read and modify bookmarks',
      'history': 'Read and modify browsing history',
      'management': 'Manage extensions and apps',
      'pageCapture': 'Save pages as MHTML',
      'proxy': 'Manage proxy settings',
      'sessions': 'Query and restore sessions',
      'topSites': 'Access most visited sites',
      'contextMenus': 'Add context menu items',
      'declarativeContent': 'Take actions based on page content',
      'declarativeNetRequest': 'Modify network requests declaratively',
      'alarms': 'Schedule tasks',
      'idle': 'Detect user idle state',
      'unlimitedStorage': 'Store unlimited data'
    };

    // Try to find matching description
    for (const [key, desc] of Object.entries(descriptions)) {
      if (permission.includes(key)) {
        return desc;
      }
    }

    return `Permission: ${permission}`;
  }

  /**
   * Get rationale map
   */
  private getRationaleMap(): Record<string, string> {
    return {
      'tabs': 'This extension needs to read tab information to organize your browsing.',
      'storage': 'This extension uses local storage to save your settings.',
      'notifications': 'This extension can send you important alerts.',
      'bookmarks': 'This extension helps you manage your bookmarks.',
      'history': 'This extension can track your reading history.'
    };
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `perm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Export permissions data
   */
  export(): string {
    return JSON.stringify({
      required: Array.from(this.requiredPermissions),
      optional: Array.from(this.optionalPermissions),
      history: this.history
    }, null, 2);
  }

  /**
   * Import permissions data
   */
  import(data: string): void {
    try {
      const parsed = JSON.parse(data);
      
      if (parsed.required) {
        this.requiredPermissions = new Set(parsed.required);
      }
      if (parsed.optional) {
        this.optionalPermissions = new Set(parsed.optional);
      }
      if (parsed.history) {
        this.history = parsed.history;
      }
    } catch (error) {
      console.error('[PermissionsManager] Import error:', error);
    }
  }
}

/**
 * Request Permission Dialog Helper
 */
export class PermissionDialogHelper {
  /**
   * Show permission request rationale
   */
  static async showRationale(
    title: string,
    message: string,
    permissions: string[]
  ): Promise<boolean> {
    // This would typically show a custom UI
    // For now, we'll use Chrome's native confirmation
    return new Promise((resolve) => {
      // In a real implementation, you'd create a proper dialog
      // This is a placeholder
      resolve(true);
    });
  }

  /**
   * Create permission request object
   */
  static createRequest(
    permissions: string[],
    rationale?: string
  ): PermissionRequest {
    return {
      permissions: permissions.map(p => ({
        type: p.includes('://') ? 'host' : 'api',
        value: p
      })),
      rationale,
      timestamp: Date.now(),
      id: `req_${Date.now()}`
    };
  }

  /**
   * Format permission for display
   */
  static formatForDisplay(permission: string): string {
    // Convert technical permission to user-friendly text
    const friendlyNames: Record<string, string> = {
      'tabs': 'View your open tabs',
      'activeTab': 'Access the current webpage',
      'storage': 'Save data on your computer',
      'cookies': 'Read and modify cookies',
      'webRequest': 'Observe and analyze web traffic',
      'notifications': 'Show you notifications',
      'bookmarks': 'Access your bookmarks',
      'history': 'Access your browsing history',
      'geolocation': 'Access your location'
    };

    for (const [key, name] of Object.entries(friendlyNames)) {
      if (permission.includes(key)) {
        return name;
      }
    }

    return permission;
  }
}

/**
 * Factory function
 */
export function createPermissionsManager(config?: PermissionConfig): PermissionsManager {
  return new PermissionsManager(config);
}

export default PermissionsManager;
