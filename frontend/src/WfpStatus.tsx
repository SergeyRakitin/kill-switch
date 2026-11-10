type ObjectState = {
  present: boolean
  persistent: boolean
  disabled: boolean
  serviceName?: string
}

type ConditionState = {
  field: string
  match?: number
  value: string
}

// FWP_MATCH_PREFIX: по документации Microsoft сравнивает конец значения.
const matchSuffix = 11

type FilterState = {
  key: string
  layer: string
  action: number | string
  weight: number
  persistent: boolean
  disabled: boolean
  conditionCount: number
  conditions: ConditionState[] | null
}

type StatusSnapshot = {
  state: string
  policyInstalled: boolean
  verified: boolean
  wfp?: {
    provider: ObjectState
    sublayer: ObjectState
    filters: FilterState[] | null
  }
  logDir: string
  error?: string
  logError?: string
}

const stateNames: Record<string, string> = {
  disabled: 'Собственные фильтры не установлены',
  degraded: 'Объекты WFP отключены или повреждены',
  unknown: 'Состояние не подтверждено',
}

const layerNames: Record<string, string> = {
  FWPM_LAYER_ALE_AUTH_CONNECT_V4: 'Исходящие IPv4',
  FWPM_LAYER_ALE_AUTH_CONNECT_V6: 'Исходящие IPv6',
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: 'Входящие IPv4',
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: 'Входящие IPv6',
}

const conditionNames: Record<string, string> = {
  FWPM_CONDITION_ALE_APP_ID: 'Приложение (хеш AppID)',
  FWPM_CONDITION_ALE_PACKAGE_ID: 'MSIX-пакет (SID)',
  FWPM_CONDITION_IP_NEXTHOP_INTERFACE: 'VPN-интерфейс (LUID)',
  FWPM_CONDITION_FLAGS: 'Флаги подключения',
}

const yesNo = (value: boolean) => value ? 'Да' : 'Нет'

function actionName(action: number | string) {
  if (action === 4097 || action === 'BLOCK') return 'Блокировать'
  if (action === 4098 || action === 'PERMIT' || action === 'PERMIT_SOFT') return 'Разрешать'
  return `Действие ${action}`
}

function ObjectCard({ title, description, object }: { title: string; description: string; object: ObjectState }) {
  return <article className="object-card">
    <h3>{title}</h3>
    <p>{description}</p>
    {object.present ? <dl>
      <div><dt>Найден</dt><dd>Да</dd></div>
      <div><dt>Постоянный</dt><dd>{yesNo(object.persistent)}</dd></div>
      <div><dt>Отключён</dt><dd>{yesNo(object.disabled)}</dd></div>
      {object.serviceName && <div><dt>Привязка</dt><dd>К службе Windows</dd></div>}
    </dl> : <p className="object-absent">Объект не создан.</p>}
  </article>
}

export function WfpStatus({ raw }: { raw: string }) {
  let snapshot: StatusSnapshot
  try {
    snapshot = JSON.parse(raw) as StatusSnapshot
  } catch {
    return <details><summary>Исходный JSON</summary><pre>{raw}</pre></details>
  }
  if (!snapshot.wfp?.provider || !snapshot.wfp.sublayer || !Array.isArray(snapshot.wfp.filters)) {
    return <div className="wfp-status">
      <p className="warning">{snapshot.error ?? 'Снимок WFP неполный или не получен.'}</p>
      {snapshot.logDir && <p className="log-path">Каталог журналов: <code>{snapshot.logDir}</code></p>}
      <details><summary>Исходный JSON</summary><pre>{raw}</pre></details>
    </div>
  }
  const filters = snapshot.wfp.filters ?? []
  return <div className="wfp-status">
    <dl className="status-summary">
      <div><dt>Состояние</dt><dd>{stateNames[snapshot.state] ?? snapshot.state}</dd></div>
      <div><dt>Политика</dt><dd>{snapshot.policyInstalled ? 'Установлена' : 'Не установлена'}</dd></div>
      <div><dt>Фильтров</dt><dd>{filters.length}</dd></div>
      <div><dt>Проверка CLI</dt><dd>{snapshot.verified ? 'Подтверждена' : 'Не выполнена'}</dd></div>
    </dl>
    <div className="object-grid">
      <ObjectCard title="Provider" description="Контейнер объектов kill switch" object={snapshot.wfp.provider} />
      <ObjectCard title="Sublayer" description="Подслой правил kill switch" object={snapshot.wfp.sublayer} />
    </div>
    <h3 className="filter-title">Собственные фильтры</h3>
    {filters.length ? <ul className="filter-list">
      {filters.map(filter => <li key={filter.key}>
        <div className="filter-heading">
          <strong>{actionName(filter.action)} · {layerNames[filter.layer] ?? filter.layer}</strong>
          <span className="badge">{filter.disabled ? 'Отключён' : filter.persistent ? 'Постоянный' : 'Временный'}</span>
        </div>
        <dl className="filter-facts">
          <div><dt>Приоритет</dt><dd>{filter.weight}</dd></div>
          <div><dt>Условий</dt><dd>{filter.conditionCount}</dd></div>
        </dl>
        {!!filter.conditions?.length && <details><summary>Условия фильтра</summary>
          <dl className="condition-list">
            {filter.conditions.map((condition, index) => <div key={index}>
              <dt>{condition.field === 'FWPM_CONDITION_ALE_APP_ID' && condition.match === matchSuffix ? 'Приложение (окончание пути)' : conditionNames[condition.field] ?? condition.field}</dt>
              <dd><code>{condition.value}</code></dd>
            </div>)}
          </dl>
        </details>}
      </li>)}
    </ul> : <p className="empty">Собственные фильтры не найдены.</p>}
    {snapshot.logDir && <p className="log-path">Каталог журналов: <code>{snapshot.logDir}</code></p>}
    {snapshot.logError && <p className="warning">{snapshot.logError}</p>}
    <details><summary>Исходный JSON</summary><pre>{raw}</pre></details>
  </div>
}
