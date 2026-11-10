import { Call } from '@wailsio/runtime'

export type Target = { id: string; type?: 'exe' | 'msix' | 'name'; path: string; enabled: boolean }
export type Adapter = { name: string; description: string; guid: string; status: string; luid: string }
export type Package = { name: string; packageFamilyName: string; version: string; installLocation: string }
export type Status = 'unknown' | 'active' | 'disabled' | 'error'
export type Event = { time: string; level: 'info' | 'success' | 'warning' | 'error'; message: string }
export type View = {
  settings: { schemaVersion: number; vpnInterfaceName: string; vpnInterfaceGuid?: string; networkAdapterTypes: string[] | null; targets: Target[] | null }
  adapters: Adapter[] | null
  status: Status
  reason: string
  vpnStatus: 'connected' | 'disconnected' | 'unknown'
  verifiedPaths: string[] | null
  verifiedTargetIds: string[] | null
  installedPaths: string[] | null
  filterCount: number
  objectsPresent: boolean
  configDirty: boolean
  rawStatus: string
  diagnostic: string
  events: Event[] | null
  busy: boolean
  error: string
}
export type Preview = { fingerprint: string; apps: string[] | null; addCount: number; deleteCount: number; raw: string; warnings: string[] | null }

const call = <T>(method: string, ...args: unknown[]) =>
  Call.ByName('kill-switch/internal/desktop.Service.' + method, ...args) as Promise<T>

export const api = {
  refresh: () => call<View>('Refresh'),
  preview: () => call<Preview>('Preview'),
  apply: (fingerprint: string) => call<View>('Apply', fingerprint, true),
  remove: () => call<View>('Remove', true),
  canary: () => call<View>('Canary', true),
  setTarget: (id: string, enabled: boolean, confirmed: boolean) => call<View>('SetTarget', id, enabled, confirmed),
  browseTarget: (id: string) => call<View>('BrowseTarget', id),
  addPackageTarget: (family: string) => call<View>('AddPackageTarget', family),
  addNameTarget: (name: string) => call<View>('AddNameTarget', name),
  listPackages: () => call<Package[]>('Packages'),
  removeTarget: (id: string) => call<View>('RemoveTarget', id, true),
  selectAdapter: (guid: string) => call<View>('SelectAdapter', guid),
  clearEvents: () => call<View>('ClearEvents'),
  snapshot: () => call<View>('Snapshot'),
}
