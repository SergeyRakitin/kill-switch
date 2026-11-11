import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Activity, AppWindow, Check, CircleAlert, CircleHelp, Code2, Sparkles, ClipboardCopy, Download, EllipsisVertical, FileSearch, FileText, FlaskConical, House, Info, LayoutGrid, Monitor, Plus, RefreshCw, Settings, Shield, ShieldCheck, Terminal, Trash2, TriangleAlert, LoaderCircle, X } from 'lucide-react'
import { Clipboard } from '@wailsio/runtime'
import { api, type Event, type Package, type Preview, type Target, type View } from './api'
import { WfpStatus } from './WfpStatus'
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
  onSuccess?: (result: View) => void
  onFailure?: (message: string, result: View | null) => void
  // Форма ввода: окно закрывается только после успеха, ошибки показываются в нём же.
  inline?: boolean
  // Проверка введённого до обращения к сервису; возвращает текст ошибки или пустую строку.
  validate?: () => string
}

const states = {
  active: ['Защита активна', 'Применённые правила ограничивают доступ выбранных приложений через VPN.'],
  disabled: ['Защита выключена', 'Установите правила WFP для выбранных приложений.'],
  error: ['Ошибка защиты', 'Подробности проверки доступны в диагностике.'],
  unknown: ['Статус защиты неизвестен', 'Проверяем правила WFP и состояние VPN-интерфейса.'],
}

const filename = (path: string) => path.split(/[\\/]/).at(-1) || path
// Сервис передаёт цели как путь EXE, msix:семейство или name:имя EXE.
const describeTarget = (value: string) => value.startsWith('name:') ? `${value.slice(5)} — в любой папке` :
  value.startsWith('msix:') ? `${value.slice(5)} — MSIX` : value
// Те же правила, что у config.ValidFileName на стороне Go, но с понятным текстом для каждой ошибки.
function fileNameProblem(raw: string) {
  const name = raw.trim()
  if (!name) return 'Введите имя EXE, например claude.exe.'
  if (/[\\/:]/.test(name)) return 'Нужно только имя файла без папки: claude.exe, а не полный путь.'
  if (/[*?<>"|]/.test(name)) return 'Маски и символы * ? < > " | в имени недопустимы.'
  if (!/^[\x20-\x7e]+$/.test(name)) return 'Имя пишется латиницей: кириллица и другие не-ASCII символы не поддерживаются.'
  if (!/\.exe$/i.test(name)) return 'Имя должно оканчиваться на .exe.'
  if (/^[. ]*$/.test(name.slice(0, -4))) return 'Перед .exe должно быть имя файла.'
  if (name.length > 255) return 'Имя длиннее 255 символов.'
  return ''
}
const presetNames: Record<string, string> = { probe: 'Тестовый клиент', claude: 'Claude', codex: 'Codex' }
const targetName = (target: Target) => presetNames[target.id] ?? (target.type === 'msix' ? target.path : filename(target.path))
const detailsTitle = (target: Target) => target.type === 'msix' ? 'Подробности MSIX' : target.type === 'name' ? 'Подробности правила по имени' : 'Подробности EXE'
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

// Какие фильтры WFP создаёт каждый способ указать приложение; показывается подсказкой у заголовка списка.
const filterSet = 'Фильтры на каждую запись: разрешение исходящих через VPN, блокировка остальных исходящих и всех входящих (IPv4 и IPv6).'
const ruleHints = {
  name: `Условие WFP: путь приложения оканчивается на \\имя.exe (ALE_APP_ID, сравнение конца пути).\n${filterSet}`,
  path: `Условие WFP: полный путь приложения совпадает с выбранным файлом (ALE_APP_ID, точное сравнение).\n${filterSet}`,
  msix: `Условие WFP: SID контейнера приложения (ALE_PACKAGE_ID). Срабатывает только в песочнице AppContainer.\n${filterSet}`,
}

function Hint({ text }: { text: string }) {
  return <span className="hint has-tip" tabIndex={0} role="note" aria-label={text} data-tip={text}><CircleHelp size={15} /></span>
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

function ConfirmDialog({ confirmation, onClose, onConfirm, onSubmit }: {
  confirmation: Confirmation; onClose: () => void; onConfirm: () => void; onSubmit: () => Promise<string>
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [problem, setProblem] = useState('')
  const [pending, setPending] = useState(false)
  const focusField = () => dialog.current?.querySelector<HTMLElement>('[data-autofocus]')?.focus()
  useEffect(() => {
    const element = dialog.current
    element?.showModal()
    focusField()
    return () => element?.close()
  }, [])
  async function submit() {
    const invalid = confirmation.validate?.() ?? ''
    if (invalid) {
      setProblem(invalid)
      focusField()
      return
    }
    setProblem('')
    setPending(true)
    // При успехе окно закрывается вызывающей стороной, поэтому состояние меняем только при ошибке.
    const failure = await onSubmit()
    if (failure) {
      setPending(false)
      setProblem(failure)
      focusField()
    }
  }
  const content = <>
    <div className="dialog-body">
      {confirmation.detail}
      {problem && <p className="error field-error" role="alert">{problem}</p>}
    </div>
    <footer className="dialog-actions">
      <button type="button" className="button" autoFocus onClick={onClose}>{confirmation.run ? 'Отмена' : 'Закрыть'}</button>
      {confirmation.run && <button type={confirmation.inline ? 'submit' : 'button'} className={'button ' + (confirmation.danger ? 'danger' : 'primary')} disabled={pending} onClick={confirmation.inline ? undefined : onConfirm}>{pending ? 'Выполняется…' : confirmation.label}</button>}
    </footer>
  </>
  return <dialog ref={dialog} onCancel={event => { event.preventDefault(); onClose() }} aria-labelledby="confirm-title">
    <header className="panel-title">
      <h2 id="confirm-title"><Shield size={17} />{confirmation.title}</h2>
      <button className="icon-button" aria-label="Закрыть" onClick={onClose}><X size={16} /></button>
    </header>
    {confirmation.inline ?
      <form className="dialog-form" noValidate onSubmit={event => { event.preventDefault(); if (!pending) void submit() }} onInput={() => setProblem('')}>{content}</form> :
      content}
  </dialog>
}

function PreviewDetails({ preview }: { preview: Preview }) {
  const guid = (() => {
    try { return (JSON.parse(preview.raw) as { interface?: { guid?: string } }).interface?.guid }
    catch { return undefined }
  })()
  return <>
    <p>Добавить правил WFP: <strong>{preview.addCount}</strong>. Удалить: <strong>{preview.deleteCount}</strong>.</p>
    {preview.apps?.length ? <ul className="paths">{preview.apps.map(path => <li key={path}>{describeTarget(path)}</li>)}</ul> :
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
  const [loading, setLoading] = useState(true)
  const [changesFilters, setChangesFilters] = useState(false)
  const [error, setError] = useState('')
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [menu, setMenu] = useState<string | null>(null)
  const [journalCopied, setJournalCopied] = useState(false)
  const [diagnosticCopied, setDiagnosticCopied] = useState(false)
  const inFlight = useRef(false)
  const modalOpen = useRef(false)
  const main = useRef<HTMLElement>(null)
  const packageInput = useRef<HTMLInputElement>(null)
  const packageSelect = useRef<HTMLSelectElement>(null)
  const nameInput = useRef<HTMLInputElement>(null)

  async function perform<T>(action: () => Promise<T>, accept: (result: T) => void, reject?: (message: string, result: View | null) => void) {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    setError('')
    try {
      accept(await action())
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : String(failure)
      setError(message)
      let latest: View | null = null
      try {
        latest = await api.snapshot()
        setView(latest)
      } catch { /* The desktop bridge may be unavailable. */ }
      reject?.(message, latest)
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  const update = (action: () => Promise<View>) => void perform(action, setView)
  const ask = (next: Confirmation) => { modalOpen.current = true; setConfirmation(next) }
  const dismiss = () => { modalOpen.current = false; setConfirmation(null) }

  // Выполняет форму, не закрывая окно: пустая строка — успех, иначе текст ошибки для показа в окне.
  async function submitInline(next: Confirmation): Promise<string> {
    if (!next.run) return ''
    if (inFlight.current) return 'Дождитесь завершения текущей операции.'
    inFlight.current = true
    setBusy(true)
    try {
      const result = await next.run()
      setView(result)
      dismiss()
      next.onSuccess?.(result)
      return ''
    } catch (failure) {
      return failure instanceof Error ? failure.message : String(failure)
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  useEffect(() => {
    const refresh = () => {
      if (!modalOpen.current) void perform(api.refresh, setView)
    }
    // Первое чтение WFP и адаптеров занимает несколько секунд: до его конца вместо страницы — плашка загрузки.
    void perform(api.refresh, setView).finally(() => setLoading(false))
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

  useEffect(() => {
    const selectOutput = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.code !== 'KeyA') return
      if (event.target instanceof Element && event.target.closest('dialog, input, textarea, [contenteditable="true"]')) return
      const region = main.current?.querySelector<HTMLElement>('[data-selectable-region]')
      if (!region) return
      event.preventDefault()
      event.stopPropagation()
      region.focus({ preventScroll: true })
      const range = document.createRange()
      range.selectNodeContents(region)
      const selection = window.getSelection()
      selection?.removeAllRanges()
      selection?.addRange(range)
    }
    document.addEventListener('keydown', selectOutput, true)
    return () => document.removeEventListener('keydown', selectOutput, true)
  }, [route])

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
  const isVerified = (target: Target) => status === 'active' && target.enabled && (view?.verifiedTargetIds ?? []).includes(target.id)
  const installedPaths = view?.installedPaths ?? []
  // Сводка: число приложений каждого вида; полный список — во всплывающей подсказке.
  const installedNames = installedPaths.filter(path => path.startsWith('name:')).map(path => path.slice(5))
  const installedPackages = installedPaths.filter(path => path.startsWith('msix:')).map(path => path.slice(5))
  const installedFiles = installedPaths.filter(path => !path.startsWith('name:') && !path.startsWith('msix:'))
  const installedGroups = [
    { label: 'По имени', items: installedNames, list: installedNames.join(', ') },
    { label: 'По пути', items: installedFiles, list: '\n' + installedFiles.join('\n') },
    { label: 'MSIX', items: installedPackages, list: installedPackages.join(', ') },
  ].filter(group => group.items.length)
  const installedSummary = installedPaths.length ? installedGroups.map(group => `${group.label}: ${group.items.length}`).join(' · ') :
    status === 'disabled' ? 'Нет установленных правил' : 'Список не подтверждён'
  const installedDetails = installedGroups.map(group => `${group.label}: ${group.list}`).join('\n')
  const missingIds = view?.missingTargetIds ?? []
  const isMissing = (target: Target) => missingIds.includes(target.id)
  // Включённая запись с пропавшим файлом не даёт построить план: установку блокируем, пока запись не исправят.
  const blockedByMissing = targets.some(target => target.enabled && isMissing(target))
  const canInstall = available && !blockedByMissing && !(status === 'active' && !view?.configDirty)
  const filterSummary = status === 'error' ? 'Ошибка чтения' : status === 'unknown' ? 'Не проверено' :
    view?.objectsPresent ? `Фильтров: ${view.filterCount}` : 'Объекты не обнаружены'
  const errorText = error || view?.error

  const inspectPlan = () => void perform(api.preview, preview => ask({
    title: 'Что изменится в WFP',
    detail: <><p>Только предпросмотр. Ничего не применяется.</p><PreviewDetails preview={preview} /></>,
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
  const canaryFailureSummary = (result: View | null) => {
    if (!result) return 'После ошибки состояние WFP прочитать не удалось. Выполненные шаги указаны в диагностике.'
    if (result.objectsPresent) return `После ошибки обнаружены собственные объекты WFP (фильтров: ${result.filterCount}). Это могут быть ранее установленные правила или объекты незавершённой проверки. Подробности — в диагностике.`
    if (result.status === 'disabled') return 'Контрольное чтение после ошибки: собственные объекты WFP не обнаружены. Какие шаги были выполнены, указано в диагностике.'
    return 'Итоговое состояние WFP после ошибки не подтверждено. Выполненные шаги указаны в диагностике.'
  }
  const canary = () => ask({
    title: 'Проверить запись в WFP?',
    label: 'Проверить',
    detail: <p>Будут созданы и удалены служебные объекты WFP без сетевых фильтров. VPN и трафик не проверяются. Если собственные объекты уже существуют, проверка отклоняется без изменения.</p>,
    run: api.canary,
    changesFilters: true,
    onSuccess: () => ask({
      title: 'Запись в WFP работает',
      detail: <>
        <p className="success"><strong>Проверка успешно завершена.</strong></p>
        <p>Созданы служебные объекты WFP: provider и sublayer. Их наличие подтверждено повторным чтением.</p>
        <p>Затем оба объекта удалены. Контрольное чтение подтвердило, что собственных объектов WFP не осталось.</p>
        <p>Сетевые фильтры не создавались. VPN и трафик не проверялись.</p>
      </>,
    }),
    onFailure: (message, result) => ask({
      title: 'Проверка записи в WFP не выполнена',
      detail: <>
        <p className="error">{message}</p>
        <p>{canaryFailureSummary(result)}</p>
        <button className="text-button" onClick={() => { dismiss(); navigate('diagnostics') }}>Открыть диагностику</button>
      </>,
    }),
  })
  const copyJournal = () => void perform(
    () => Clipboard.SetText(events.map(event => `${event.time}\t${event.level}\t${event.message}`).join('\r\n')),
    () => setJournalCopied(true),
  )
  const copyDiagnostic = () => void perform(
    () => Clipboard.SetText(view?.diagnostic ?? ''),
    () => setDiagnosticCopied(true),
  )

  const addPackage = () => void perform(api.listPackages, (packages: Package[]) => ask({
    title: 'Добавить MSIX-пакет',
    label: 'Добавить пакет',
    detail: <>
      <p>Правило по пакету действует только на приложения в изолированной песочнице Windows (AppContainer).</p>
      <p className="warning">Claude Desktop и другие приложения без песочницы так не защищаются: для них используйте «Добавить имя» в списке «EXE по имени».</p>
      <label htmlFor="package-choice">Установленное приложение</label>
      <select id="package-choice" ref={packageSelect} disabled={!packages.length} autoFocus>
        {packages.length ? packages.map(p => <option key={p.packageFamilyName} value={p.packageFamilyName} title={p.installLocation}>{p.name} · {p.version} · {p.packageFamilyName}</option>) : <option value="">Установленные пакеты не найдены</option>}
      </select>
      <label htmlFor="package-family">Или package family вручную</label>
      <input id="package-family" ref={packageInput} defaultValue="" placeholder="Claude_pzs8sxrjxfjjc" spellCheck={false} />
    </>,
    run: () => api.addPackageTarget(packageInput.current?.value.trim() || packageSelect.current?.value || ''),
  }))

  const addName = () => ask({
    title: 'Добавить EXE по имени',
    label: 'Добавить',
    inline: true,
    detail: <>
      <p>Правило совпадёт с EXE с этим именем в любой папке. Защита сохраняется, когда обновление кладёт новую версию в новый каталог, как у Claude Desktop и Claude Code.</p>
      <p className="warning">Под правило попадёт любой файл с таким именем. Если приложение переименует свой EXE, правило перестанет на него действовать.</p>
      <p>Для Claude: <code>claude.exe</code> и <code>cowork-svc.exe</code>.</p>
      <label htmlFor="file-name">Имя EXE</label>
      <input id="file-name" ref={nameInput} defaultValue="" placeholder="claude.exe" spellCheck={false} autoComplete="off" data-autofocus />
    </>,
    validate: () => fileNameProblem(nameInput.current?.value ?? ''),
    run: () => api.addNameTarget(nameInput.current?.value.trim() ?? ''),
  })

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
        <button onClick={() => ask({ title: detailsTitle(target), detail: <>
          <strong>{targetName(target)}</strong>
          <code>{target.path === 'Z' ? 'Путь не выбран' : target.path}</code>
          {target.type === 'name' && <p>Совпадает с EXE с этим именем в любой папке.</p>}
        </> })}>{detailsTitle(target)}</button>
        {target.type !== 'msix' && target.type !== 'name' && <button onClick={() => update(() => api.browseTarget(target.id))}>Выбрать другой EXE</button>}
        {target.id !== 'probe' && <button className="error" onClick={() => ask({
          title: 'Удалить приложение из списка?',
          label: 'Удалить приложение',
          detail: <code className="break-all">{target.path}</code>,
          run: () => api.removeTarget(target.id),
          danger: true,
        })}>Удалить из списка</button>}
      </div>}
    </div>
  </>

  const msixTargets = targets.filter(target => target.type === 'msix')
  const nameTargets = targets.filter(target => target.type === 'name')
  const exeTargets = targets.filter(target => target.type !== 'msix' && target.type !== 'name')
  const renderTarget = (target: Target) => {
    const executable = filename(target.path).toLowerCase()
    const Glyph = executable === 'claude.exe' ? Sparkles : executable === 'codex.exe' ? Code2 : /probe|code|terminal|powershell|cmd/i.test(executable) ? Terminal : AppWindow
    const verified = isVerified(target)
    return <li key={target.id}>
      <span className={'app-icon ' + (executable === 'claude.exe' ? 'claude' : executable === 'codex.exe' ? 'codex' : target.id)}><Glyph size={18} /></span>
      <div className="app-copy"><strong>{targetName(target)}</strong><small title={target.path === 'Z' ? undefined : target.path}>{target.path === 'Z' ? 'Путь к EXE не выбран' : target.type === 'name' ? 'В любой папке' : target.path}</small></div>
      {isMissing(target) ?
        <span className="badge missing" title="Файла по этому пути нет: удалите запись или выберите EXE заново"><TriangleAlert size={12} />Файл не найден</span> :
        <span className={'badge ' + (verified ? 'verified' : '')}>{verified ? <ShieldCheck size={12} /> : <Shield size={12} />}{verified ? 'Через VPN' : target.enabled ? 'Не подтверждено' : 'Выключено'}</span>}
      {targetActions(target)}
    </li>
  }

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
      {loading ? <div className="loading-plate" role="status" aria-live="polite">
        <LoaderCircle className="animate-spin motion-reduce:animate-none" size={22} />
        <div><strong>Загрузка…</strong><small>Читаем правила WFP и сетевые адаптеры. Это занимает несколько секунд.</small></div>
      </div> : <>
      {errorText && !(route === 'home' && status === 'error') && <div className="error-banner" role="alert"><CircleAlert size={17} /><div><strong>{view ? 'Операция завершилась с ошибкой' : 'Сервис Wails недоступен'}</strong>{route === 'diagnostics' ? <div>{errorText}</div> : <button className="text-button" onClick={() => navigate('diagnostics')}>Диагностика</button>}</div><button className="icon-button" aria-label="Скрыть сообщение" disabled={!error} onClick={() => setError('')}><X size={16} /></button></div>}

      {route === 'home' ? <div className="dashboard">
        <section className={'hero ' + statusClass}>
          <ShieldCheck className="hero-icon" size={48} strokeWidth={1.65} />
          <div><h1>{changesFilters ? 'Выполняется операция' : statusTitle}</h1><p>{!view && !busy ? 'Состояние защиты доступно в настольном приложении.' : statusDetail}</p></div>
          <Switch checked={status === 'active'} label="Правила WFP установлены" disabled={!available || (status !== 'active' && blockedByMissing)} onChange={status === 'active' ? remove : install} />
        </section>
        <section className="panel status-panel">
          <PanelTitle>Состояние</PanelTitle>
          <ul>
            <li><span className={'status-icon ' + (status === 'active' ? 'good' : '')}>{status === 'active' ? <Check size={15} /> : <CircleHelp size={15} />}</span><div><strong>Фильтры WFP</strong><small>{filterSummary}</small></div></li>
            <li><span className={'status-icon ' + (view?.vpnStatus === 'connected' ? 'good' : '')}>{view?.vpnStatus === 'connected' ? <Check size={15} /> : <CircleHelp size={15} />}</span><div><strong>VPN-интерфейс</strong><small>{vpnName} · {vpnStatus}</small></div></li>
            <li><span className={'status-icon ' + (installedPaths.length ? 'good' : '')}>{installedPaths.length ? <Check size={15} /> : <CircleHelp size={15} />}</span>{installedPaths.length ?
              <div className="has-tip fill installed-summary" tabIndex={0} data-tip={installedDetails} aria-label={'Правила установлены для приложений. ' + installedDetails}><strong>Правила установлены для приложений</strong><small>{installedSummary}</small></div> :
              <div><strong>Правила установлены для приложений</strong><small>{installedSummary}</small></div>}</li>
          </ul>
          {view?.configDirty && !blockedByMissing && <p className="warning pending-changes">Есть изменения, установите новые правила.</p>}
          {blockedByMissing && <p className="warning pending-changes">Установка правил недоступна: файлы некоторых записей «EXE по точному пути» не найдены. Удалите или выключите эти записи либо выберите EXE заново.</p>}
        </section>
        <section className="panel apps">
          <PanelTitle icon={<LayoutGrid size={17} />} action={<button className="button primary compact" disabled={!available} onClick={addName}><Plus size={15} />Добавить имя</button>}>
            EXE по имени (любая папка) <span className="counter">{nameTargets.length}</span><Hint text={ruleHints.name} />
          </PanelTitle>
          <p>Правила применяются ко всем Exe-файлам с указанным именем вне зависимости от местоположения. Подходит для приложений, которые при обновлении устанавливаются по новому пути, например, Claude Desktop.</p>
          <ul className="app-list">{nameTargets.map(renderTarget)}</ul>
          {!nameTargets.length && <p className="empty">Добавьте имя EXE, например claude.exe.</p>}
        </section>
        <section className="panel apps">
          <PanelTitle icon={<LayoutGrid size={17} />} action={<button className="button primary compact" disabled={!available} onClick={() => update(() => api.browseTarget(''))}><Plus size={15} />Добавить путь</button>}>
            EXE по точному пути <span className="counter">{exeTargets.length}</span><Hint text={ruleHints.path} />
          </PanelTitle>
          <p>Правила применяются к Exe-файлам с указанным точным расположением.</p>
          <ul className="app-list">{exeTargets.map(renderTarget)}</ul>
          {!exeTargets.length && <p className="empty">{view ? 'Добавьте EXE приложения, которое должно работать через VPN.' : 'Конфигурация пока недоступна.'}</p>}
        </section>
        <section className="panel apps">
          <PanelTitle icon={<LayoutGrid size={17} />} action={<button className="button primary compact" disabled={!available} onClick={addPackage}><Plus size={15} />Добавить пакет</button>}>
            Пакеты MSIX (Windows App) <span className="counter">{msixTargets.length}</span><Hint text={ruleHints.msix} />
          </PanelTitle>
          <p>Правила применяются ко всем exe-файлам по имени пакета MSIX (Windows App из Microsoft Store), вне зависимости от имени и местоположения файла.</p>
          <ul className="app-list">{msixTargets.map(renderTarget)}</ul>
          {!msixTargets.length && <p className="empty">Добавьте Windows App, которое должно работать только через VPN.</p>}
        </section>
        <div className="main-actions">
          <button className="button primary" disabled={!canInstall} onClick={install}><Download size={16} />Установить правила</button>
          <button className="button" disabled={!available || (status === 'disabled' && !view?.objectsPresent)} onClick={remove}><Trash2 size={16} />Удалить правила</button>
          <button className="button secondary" disabled={busy || view?.busy} onClick={() => update(api.refresh)}><RefreshCw size={16} />Обновить статус</button>
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
          {view?.rawStatus && <WfpStatus raw={view.rawStatus} />}
        </section>}
        {route === 'diagnostics' && <section className="panel content-panel">
          <PanelTitle icon={<Activity size={18} />} action={<button className="button compact" disabled={!available || !view?.diagnostic} onClick={copyDiagnostic}><ClipboardCopy size={14} />Копировать</button>}>{statusTitle}</PanelTitle>
          <p>{view?.reason || statusDetail}</p>
          <div className="flex flex-wrap gap-2">
            <button className="button secondary" disabled={busy} onClick={() => { setDiagnosticCopied(false); update(api.refresh) }}><RefreshCw size={16} />Обновить диагностику</button>
            <button className="button" disabled={!available} onClick={inspectPlan}><FileSearch size={16} />Что изменится в WFP</button>
            <button className="button" disabled={!available} onClick={canary}><FlaskConical size={16} />Проверить запись в WFP</button>
          </div>
          {diagnosticCopied && <p role="status" className="success">Диагностика скопирована в буфер обмена.</p>}
          <div className="selectable-output" data-selectable-region tabIndex={0}>
            {view?.diagnostic ? <pre>{view.diagnostic}</pre> : <p className="empty">Диагностика пока пуста.</p>}
          </div>
        </section>}
        {route === 'journal' && <section className="panel content-panel">
          <PanelTitle icon={<FileText size={18} />} action={<div className="flex flex-wrap gap-2">
            <button className="button compact" disabled={!available || !events.length} onClick={copyJournal}><ClipboardCopy size={14} />Копировать</button>
            <button className="button compact" disabled={!available || !events.length} onClick={() => { setJournalCopied(false); update(api.clearEvents) }}><Trash2 size={14} />Очистить</button>
          </div>}>Журнал событий</PanelTitle>
          {journalCopied && <p role="status" className="success">Журнал скопирован в буфер обмена.</p>}
          <div className="selectable-output" data-selectable-region tabIndex={0}><EventList events={events} /></div>
        </section>}
        {route === 'about' && <section className="panel content-panel">
          <PanelTitle icon={<ShieldCheck size={18} />}>VPN Kill Switch</PanelTitle>
          <p>Утилита Windows для управления правилами Windows Filtering Platform (WFP) для выбранных приложений.</p>
          <p>Постоянные правила WFP сохраняются при закрытии окна. Удалить их можно в разделе «Правила WFP».</p>
        </section>}
      </>}
      </>}
    </main>
    {confirmation && <ConfirmDialog confirmation={confirmation} onClose={dismiss} onSubmit={() => submitInline(confirmation)} onConfirm={() => {
      dismiss()
      if (!confirmation.run) return
      setChangesFilters(Boolean(confirmation.changesFilters))
      void perform(confirmation.run, result => {
        setView(result)
        confirmation.onSuccess?.(result)
      }, confirmation.onFailure).finally(() => setChangesFilters(false))
    }} />}
  </div>
}

export default App
