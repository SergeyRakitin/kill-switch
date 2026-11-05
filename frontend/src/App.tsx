import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Activity, AppWindow, Check, ChevronRight, CircleAlert, CircleHelp, Code2, Sparkles, ClipboardCopy, Download, EllipsisVertical, FileSearch, FileText, FlaskConical, House, Info, LayoutGrid, Monitor, Play, Plus, RefreshCw, Settings, Shield, ShieldCheck, Terminal, Trash2, X } from 'lucide-react'
import { Clipboard } from '@wailsio/runtime'
import { api, type Event, type Preview, type Target, type View } from './api'
import './style.css'

const routes = [
  ['home', 'Главная', House],
  ['settings', 'Настройки', Settings],
  ['rules', 'Правила WFP', ShieldCheck],
  ['diagnostics', 'Диагностика', Activity],
  ['journal', 'Журнал', FileText],
  ['about', 'О программе', Info],
] as const

type Route = typeof routes[number][0]
type Confirmation = {
  title: string
  label?: string
  detail: ReactNode
  run?: () => Promise<View>
  danger?: boolean
  changesFilters?: boolean
}

const states = {
  active: ['Защита активна', 'Применённые правила ограничивают доступ выбранных приложений через VPN.'],
  disabled: ['Защита выключена', 'Установите правила WFP для выбранных приложений.'],
  error: ['Ошибка защиты', 'Подробности проверки доступны в диагностике.'],
  unknown: ['Статус защиты неизвестен', 'Проверяем правила WFP и состояние VPN-интерфейса.'],
}

const filename = (path: string) => path.split(/[\\/]/).at(-1) || path
const presetNames: Record<string, string> = { probe: 'Тестовый клиент', claude: 'Claude', codex: 'Codex' }
const targetName = (target: Target) => presetNames[target.id] ?? filename(target.path)
const adapterGuid = (view: View | null) => view?.settings.vpnInterfaceGuid ?? ''
const same = (left: string, right: string) => left.toLowerCase() === right.toLowerCase()

function Switch({ checked, label, disabled, onChange }: {
  checked: boolean; label: string; disabled?: boolean; onChange: () => void
}) {
  return <button type="button" className="switch" role="switch" aria-label={label} aria-checked={checked} disabled={disabled} onClick={onChange}><span /></button>
}

function PanelTitle({ icon, children, action }: { icon?: ReactNode; children: ReactNode; action?: ReactNode }) {
  return <header className="panel-title"><h2>{icon}{children}</h2>{action}</header>
}

function EventList({ events, compact = false }: { events: Event[]; compact?: boolean }) {
  return events.length ? <ul className="event-list">
    {events.map((event, index) => {
      const Icon = event.level === 'success' ? Check : event.level === 'info' ? Info : CircleAlert
      const date = new Date(event.time)
      return <li key={event.time + '-' + index}>
        <Icon className={event.level} size={14} />
        <time title={event.time}>{Number.isNaN(date.valueOf()) ? event.time : date.toLocaleTimeString('ru-RU')}</time>
        <span className={compact ? 'compact-message' : ''} title={compact ? event.message : undefined}>{compact && event.level === 'error' ? (event.message.includes('ERROR_ACCESS_DENIED') ? 'Нет прав администратора для WFP. Подробности — в диагностике.' : 'Ошибка операции. Подробности — в диагностике.') : event.message}</span>
      </li>
    })}
  </ul> : <p className="empty">Событий пока нет.</p>
}

function ConfirmDialog({ confirmation, onClose, onConfirm }: {
  confirmation: Confirmation; onClose: () => void; onConfirm: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const element = dialog.current
    element?.showModal()
    return () => element?.close()
  }, [])
  return <dialog ref={dialog} onCancel={event => { event.preventDefault(); onClose() }} aria-labelledby="confirm-title">
    <header className="panel-title">
      <h2 id="confirm-title"><Shield size={17} />{confirmation.title}</h2>
      <button className="icon-button" aria-label="Закрыть" onClick={onClose}><X size={16} /></button>
    </header>
    <div className="dialog-body">{confirmation.detail}</div>
    <footer className="dialog-actions">
      <button className="button" autoFocus onClick={onClose}>{confirmation.run ? 'Отмена' : 'Закрыть'}</button>
      {confirmation.run && <button className={'button ' + (confirmation.danger ? 'danger' : 'primary')} onClick={onConfirm}>{confirmation.label}</button>}
    </footer>
  </dialog>
}

function PreviewDetails({ preview }: { preview: Preview }) {
  const guid = (() => {
    try { return (JSON.parse(preview.raw) as { interface?: { guid?: string } }).interface?.guid }
    catch { return undefined }
  })()
  return <>
    <p>Добавить правил WFP: <strong>{preview.addCount}</strong>. Удалить: <strong>{preview.deleteCount}</strong>.</p>
    {preview.apps?.length ? <ul className="paths">{preview.apps.map(path => <li key={path}>{path}</li>)}</ul> :
      <p className="warning">Нет выбранных приложений. Применение плана снимет существующие фильтры kill switch.</p>}
    {preview.warnings?.map((warning, index) => <p className="warning" key={index}>{warning}</p>)}
    <details><summary>Параметры проверки</summary>
      {guid && <p>GUID интерфейса <code>{guid}</code></p>}
      <p>Отпечаток плана <code>{preview.fingerprint}</code></p>
      {preview.raw && <pre>{preview.raw}</pre>}
    </details>
  </>
}

function App() {
  const [route, setRoute] = useState<Route>('home')
  const [view, setView] = useState<View | null>(null)
  const [busy, setBusy] = useState(false)
  const [changesFilters, setChangesFilters] = useState(false)
  const [error, setError] = useState('')
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [menu, setMenu] = useState<string | null>(null)
  const [journalCopied, setJournalCopied] = useState(false)
  const inFlight = useRef(false)
  const modalOpen = useRef(false)
  const main = useRef<HTMLElement>(null)

  async function perform<T>(action: () => Promise<T>, accept: (result: T) => void) {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    setError('')
    try {
      accept(await action())
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : String(failure)
      setError(message)
      try { setView(await api.snapshot()) } catch { /* The desktop bridge may be unavailable. */ }
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  const update = (action: () => Promise<View>) => void perform(action, setView)
  const ask = (next: Confirmation) => { modalOpen.current = true; setConfirmation(next) }
  const dismiss = () => { modalOpen.current = false; setConfirmation(null) }

  useEffect(() => {
    const refresh = () => {
      if (!modalOpen.current) void perform(api.refresh, setView)
    }
    refresh()
    const timer = window.setInterval(refresh, 60_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!menu) return
    const close = () => setMenu(null)
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') close() }
    document.addEventListener('click', close)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [menu])

  function navigate(next: Route) {
    setMenu(null)
    setRoute(next)
    main.current?.scrollTo({ top: 0 })
  }

  const available = Boolean(view) && !busy && !view?.busy
  const status = changesFilters ? 'unknown' : view?.status ?? 'unknown'
  const unavailableVPN = status === 'active' && view?.vpnStatus !== 'connected'
  const statusClass = unavailableVPN ? 'vpn-warning' : status
  const [statusTitle, statusDetail] = unavailableVPN ?
    ['VPN недоступен', 'Правила WFP подтверждены. Проверьте подключение VPN.'] :
    status === 'error' && view?.reason ? [states.error[0], view.reason] : states[status]
  const targets = view?.settings.targets ?? []
  const adapters = view?.adapters ?? []
  const events = view?.events?.slice().reverse() ?? []
  const matchingAdapter = adapters.find(adapter => adapterGuid(view) && same(adapter.guid, adapterGuid(view)))
    ?? adapters.find(adapter => !adapterGuid(view) && same(adapter.name, view?.settings.vpnInterfaceName ?? ''))
  const vpnName = matchingAdapter?.name || view?.settings.vpnInterfaceName || 'Интерфейс VPN'
  const vpnStatus = view?.vpnStatus === 'connected' ? 'Подключён' : view?.vpnStatus === 'disconnected' ? 'Отключён' : 'Статус неизвестен'
  const policyKnown = status === 'active' || status === 'disabled'
  const isVerified = (target: Target) => status === 'active' && target.enabled && (view?.verifiedTargetIds ?? []).includes(target.id)
  const verifiedCount = targets.filter(isVerified).length
  const canInstall = available && !(status === 'active' && !view?.configDirty)
  const filterSummary = status === 'error' ? 'Ошибка чтения' : status === 'unknown' ? 'Не проверено' :
    view?.objectsPresent ? `Фильтров: ${view.filterCount}` : 'Объекты не обнаружены'
  const errorText = error || view?.error

  const inspectPlan = () => void perform(api.preview, preview => ask({
    title: 'План правил WFP',
    detail: <PreviewDetails preview={preview} />,
  }))
  const install = () => void perform(api.preview, preview => ask({
    title: 'Установить правила WFP',
    label: 'Установить правила',
    detail: <PreviewDetails preview={preview} />,
    run: () => api.apply(preview.fingerprint),
    changesFilters: true,
  }))
  const remove = () => ask({
    title: 'Удалить правила WFP?',
    label: 'Удалить правила',
    detail: <p>После удаления собственных правил kill switch приложения смогут использовать обычное сетевое подключение.</p>,
    run: api.remove,
    danger: true,
    changesFilters: true,
  })
  const canary = () => ask({
    title: 'Запустить тест восстановления?',
    label: 'Запустить тест',
    detail: <p>Canary создаёт служебные объекты WFP без фильтров, затем удаляет их и проверяет восстановление. Проверка не охватывает утечки или сетевой трафик.</p>,
    run: api.canary,
    changesFilters: true,
  })
  const copyJournal = () => void perform(
    () => Clipboard.SetText(events.map(event => `${event.time}\t${event.level}\t${event.message}`).join('\r\n')),
    () => setJournalCopied(true),
  )

  const targetActions = (target: Target) => <>
    <Switch checked={target.enabled} disabled={!available || target.path === 'Z'} label={'Защищать ' + targetName(target)} onChange={() => {
      if (!target.enabled) {
        update(() => api.setTarget(target.id, true, false))
        return
      }
      ask({
        title: 'Исключить приложение из защиты?',
        label: 'Исключить',
        detail: <><p>Настройка защиты для этого приложения будет отключена.</p><code className="break-all">{target.path}</code></>,
        run: () => api.setTarget(target.id, false, true),
        danger: true,
      })
    }} />
    <div className="menu-anchor">
      <button className="icon-button more" aria-label={'Действия для ' + targetName(target)} aria-expanded={menu === target.id} disabled={!available} onClick={event => { event.stopPropagation(); setMenu(menu === target.id ? null : target.id) }}>
        <EllipsisVertical size={17} />
      </button>
      {menu === target.id && <div className="popover">
        <button onClick={() => ask({ title: 'Подробности EXE', detail: <><strong>{targetName(target)}</strong><code>{target.path === 'Z' ? 'Путь не выбран' : target.path}</code></> })}>Подробности EXE</button>
        <button onClick={() => update(() => api.browseTarget(target.id))}>Выбрать другой EXE</button>
        {target.id.startsWith('custom-') && <button className="error" onClick={() => ask({
          title: 'Удалить приложение из списка?',
          label: 'Удалить приложение',
          detail: <code className="break-all">{target.path}</code>,
          run: () => api.removeTarget(target.id),
          danger: true,
        })}>Удалить из списка</button>}
      </div>}
    </div>
  </>

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><ShieldCheck size={34} /><div><strong>VPN Kill Switch</strong><small>Защита приложений</small></div></div>
      <nav aria-label="Разделы">
        {routes.map(([id, label, Icon]) => <button key={id} title={label} aria-label={label} aria-current={route === id ? 'page' : undefined} onClick={() => navigate(id)}>
          <Icon size={17} /><span>{label}</span>
        </button>)}
      </nav>
      <footer className={'sidebar-status ' + statusClass}><span className="dot" /><div><strong>{statusTitle}</strong><small>{view?.configDirty ? 'Настройки изменены' : busy ? 'Выполняется проверка' : 'Состояние правил WFP'}</small></div></footer>
    </aside>

    <main ref={main} className="main">
      {errorText && !(route === 'home' && status === 'error') && <div className="error-banner" role="alert"><CircleAlert size={17} /><div><strong>{view ? 'Операция завершилась с ошибкой' : 'Сервис Wails недоступен'}</strong>{route === 'diagnostics' ? <div>{errorText}</div> : <button className="text-button" onClick={() => navigate('diagnostics')}>Диагностика</button>}</div><button className="icon-button" aria-label="Скрыть сообщение" disabled={!error} onClick={() => setError('')}><X size={16} /></button></div>}

      {route === 'home' ? <div className="dashboard">
        <div className="dashboard-main">
          <section className={'hero ' + statusClass}>
            <ShieldCheck className="hero-icon" size={48} strokeWidth={1.65} />
            <div><h1>{changesFilters ? 'Выполняется операция' : statusTitle}</h1><p>{!view && !busy ? 'Состояние защиты доступно в настольном приложении.' : statusDetail}</p></div>
            <Switch checked={status === 'active'} label="Правила WFP установлены" disabled={!available} onChange={status === 'active' ? remove : install} />
          </section>
          <button className="vpn-card panel" onClick={() => navigate('settings')} aria-label="Выбрать интерфейс VPN">
            <span className="vpn-icon"><Monitor size={21} /></span>
            <span className="vpn-copy"><strong>{vpnName}</strong><small className={view?.vpnStatus === 'connected' ? 'success' : ''}><span className="dot" />{vpnStatus}</small></span>
            <ChevronRight size={17} className="text-muted" />
          </button>
          <section className="panel apps">
            <PanelTitle icon={<LayoutGrid size={17} />} action={<button className="button primary compact" disabled={!available} onClick={() => update(() => api.browseTarget(''))}><Plus size={15} />Добавить приложение</button>}>
              Защищаемые приложения <span className="counter">{targets.length}</span>
            </PanelTitle>
            <ul className="app-list">
              {targets.map(target => {
                const Glyph = target.id === 'claude' ? Sparkles : target.id === 'codex' ? Code2 : /probe|code|terminal|powershell|cmd/i.test(filename(target.path)) ? Terminal : AppWindow
                const verified = isVerified(target)
                return <li key={target.id}>
                  <span className={'app-icon ' + target.id}><Glyph size={18} /></span>
                  <div className="app-copy"><strong>{targetName(target)}</strong><small title={target.path === 'Z' ? undefined : target.path}>{target.path === 'Z' ? 'Путь к EXE не выбран' : target.path}</small></div>
                  <span className={'badge ' + (verified ? 'verified' : '')}>{verified ? <ShieldCheck size={12} /> : <Shield size={12} />}{verified ? 'Через VPN' : target.enabled ? 'Не подтверждено' : 'Выключено'}</span>
                  {targetActions(target)}
                </li>
              })}
            </ul>
            {!targets.length && <p className="empty">{view ? 'Добавьте EXE приложения, которое должно работать через VPN.' : 'Конфигурация пока недоступна.'}</p>}
          </section>
          <div className="main-actions">
            <button className="button primary" disabled={!canInstall} onClick={install}><Download size={16} />Установить правила</button>
            <button className="button" disabled={!available || (status === 'disabled' && !view?.objectsPresent)} onClick={remove}><Trash2 size={16} />Удалить правила</button>
            <button className="button secondary" disabled={busy || view?.busy} onClick={() => update(api.refresh)}><RefreshCw size={16} />Обновить статус</button>
          </div>
        </div>
        <div className="dashboard-side">
          <section className="panel status-panel">
            <PanelTitle>Состояние</PanelTitle>
            <ul>
              {[
                [status === 'active', 'Фильтры WFP', filterSummary],
                [view?.vpnStatus === 'connected', 'VPN-интерфейс', view?.vpnStatus === 'connected' ? vpnName : vpnStatus],
                [verifiedCount > 0, 'Приложения', policyKnown ? `${verifiedCount} из ${targets.length} подтверждено` : 'Не подтверждено'],
              ].map(([ok, title, detail]) => <li key={String(title)}><span className={'status-icon ' + (ok ? 'good' : '')}>{ok ? <Check size={15} /> : <CircleHelp size={15} />}</span><div><strong>{title}</strong><small>{detail}</small></div></li>)}
            </ul>
          </section>
          <section className="panel canary">
            <PanelTitle icon={<FlaskConical size={17} />}>Тест Canary</PanelTitle>
            <p>Проверяет создание и удаление служебных объектов WFP без фильтров.</p>
            <button className="button secondary w-full" disabled={!available} onClick={canary}><Play size={14} />Запустить тест</button>
          </section>
        </div>
        <section className="panel dashboard-log">
          <PanelTitle icon={<FileText size={17} />} action={<button className="text-button" onClick={() => navigate('journal')}>Показать всё</button>}>Журнал событий</PanelTitle>
          <EventList events={events.slice(-3)} compact />
        </section>
      </div> : <>
        <header className="page-title"><h1>{routes.find(([id]) => id === route)?.[1]}</h1></header>
        {route === 'settings' && <section className="panel content-panel">
          <PanelTitle icon={<Monitor size={18} />}>Интерфейс VPN</PanelTitle>
          <p>Выберите интерфейс, через который защищённым приложениям разрешён доступ.</p>
          <p>Показываются AmneziaVPN, физические Wi-Fi/Ethernet и другие VPN. Категории задаются полем <code>networkAdapterTypes</code> в <code>guard-ui.json</code>; выбранный интерфейс всегда сохраняется в списке.</p>
          <label htmlFor="vpn-adapter">Сетевой адаптер</label>
          <select id="vpn-adapter" value={matchingAdapter?.guid ?? ''} disabled={!available || !adapters.length} onChange={event => update(() => api.selectAdapter(event.target.value))}>
            <option value="" disabled>{adapters.length ? 'Выберите интерфейс' : 'Нет доступных адаптеров'}</option>
            {adapters.map(adapter => <option key={adapter.guid} value={adapter.guid}>{adapter.name} · {adapter.status}</option>)}
          </select>
          {matchingAdapter && <p className="adapter-info"><span>{matchingAdapter.description}</span><code>{matchingAdapter.guid}</code></p>}
          {view?.configDirty && <p className="warning">Настройки изменены. Примените правила, чтобы обновить фильтры WFP.</p>}
          <div className="flex flex-wrap gap-2">
            <button className="button secondary" disabled={busy} onClick={() => update(api.refresh)}><RefreshCw size={16} />Обновить адаптеры</button>
            <button className="button primary" disabled={!canInstall} onClick={install}><Download size={16} />Установить правила</button>
          </div>
        </section>}
        {route === 'rules' && <section className="panel content-panel">
          <PanelTitle icon={<ShieldCheck size={18} />}>Фильтры Windows Filtering Platform</PanelTitle>
          <p>{filterSummary}</p>
          <div className="flex flex-wrap gap-2">
            <button className="button primary" disabled={!canInstall} onClick={install}><Download size={16} />Установить правила</button>
            <button className="button" disabled={!available || (status === 'disabled' && !view?.objectsPresent)} onClick={remove}><Trash2 size={16} />Удалить правила</button>
            <button className="button secondary" disabled={busy} onClick={() => update(api.refresh)}><RefreshCw size={16} />Обновить статус</button>
          </div>
          {view?.rawStatus && <details><summary>Подробный статус WFP</summary><pre>{view.rawStatus}</pre></details>}
        </section>}
        {route === 'diagnostics' && <section className="panel content-panel">
          <PanelTitle icon={<Activity size={18} />}>{statusTitle}</PanelTitle>
          <p>{view?.reason || statusDetail}</p>
          <div className="flex flex-wrap gap-2">
            <button className="button secondary" disabled={busy} onClick={() => update(api.refresh)}><RefreshCw size={16} />Обновить диагностику</button>
            <button className="button" disabled={!available} onClick={inspectPlan}><FileSearch size={16} />Проверить план</button>
            <button className="button" disabled={!available} onClick={canary}><FlaskConical size={16} />Запустить тест Canary</button>
          </div>
          {view?.diagnostic && <pre>{view.diagnostic}</pre>}
        </section>}
        {route === 'journal' && <section className="panel content-panel">
          <PanelTitle icon={<FileText size={18} />} action={<div className="flex flex-wrap gap-2">
            <button className="button compact" disabled={!available || !events.length} onClick={copyJournal}><ClipboardCopy size={14} />Копировать</button>
            <button className="button compact" disabled={!available || !events.length} onClick={() => { setJournalCopied(false); update(api.clearEvents) }}><Trash2 size={14} />Очистить</button>
          </div>}>Журнал событий</PanelTitle>
          {journalCopied && <p role="status" className="success">Журнал скопирован в буфер обмена.</p>}
          <EventList events={events} />
        </section>}
        {route === 'about' && <section className="panel content-panel">
          <PanelTitle icon={<ShieldCheck size={18} />}>VPN Kill Switch</PanelTitle>
          <p>Утилита Windows для управления правилами Windows Filtering Platform (WFP) для выбранных приложений.</p>
          <p>Постоянные правила WFP сохраняются при закрытии окна. Удалить их можно в разделе «Правила WFP».</p>
        </section>}
      </>}
    </main>
    {confirmation && <ConfirmDialog confirmation={confirmation} onClose={dismiss} onConfirm={() => {
      dismiss()
      if (!confirmation.run) return
      setChangesFilters(Boolean(confirmation.changesFilters))
      void perform(confirmation.run, setView).finally(() => setChangesFilters(false))
    }} />}
  </div>
}

export default App
