/* Shared, privacy-safe URL contract for cross-page workflow state. */
(function () {
  const phases = new Set(['model', 'findings', 'action-plan', 'evidence', 'signoff']);
  const views = new Set(['diagram', 'trust-boundaries', 'stride', 'linddun', 'controls', 'tests', 'gaps']);
  const frameworks = new Set(['STRIDE', 'LINDDUN']);
  const risks = new Set(['Critical', 'High', 'Medium', 'Low', 'Unknown']);
  const categories = new Set([
    'Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service',
    'Elevation of Privilege', 'Linking', 'Identifying', 'Non-repudiation', 'Detecting',
    'Data Disclosure', 'Unawareness & Unintervenability', 'Non-compliance',
  ]);
  const priorities = new Set(['Critical', 'High', 'Medium', 'Low']);
  const findingStatuses = new Set(['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified']);
  const findingStates = new Set(['grounded', 'hypothesis', 'needs_context', 'reviewed', 'verified', 'candidate']);
  const interactionStates = new Set(['mapped', 'deferred', 'unmapped']);
  const findingSorts = new Set(['risk', 'severity', 'framework', 'status', 'asset', 'scenario']);
  const actionTypes = new Set(['control', 'test']);
  const actionPriorities = new Set(['Critical', 'High', 'Medium', 'Low', 'Unprioritized']);
  const actionStatuses = new Set(['Open', 'In Progress', 'Implemented', 'Verified', 'Accepted Risk', 'Unknown', 'Not Run', 'Passed', 'Failed', 'Blocked']);
  const actionExecutability = new Set(['executable', 'blocked', 'unassigned', 'needs_review']);
  const actionSorts = new Set(['priority', 'type', 'status', 'owner', 'name']);
  const evidenceTypes = new Set(['gap', 'assumption']);
  const evidenceStatuses = new Set(['Open', 'Answered', 'Resolved', 'Deferred']);
  const evidenceSorts = new Set(['priority', 'status', 'owner', 'type', 'area']);
  const selectionPattern = /^(threat|boundary|zone|dfd-node|dfd-flow|control|test|gap|assumption):[A-Za-z0-9._:-]{1,128}$/;
  const idPattern = /^[A-Za-z0-9._:-]{1,128}$/;

  function safeSet(value, allowed) { return allowed.has(value) ? value : ''; }
  function read() {
    const params = new URLSearchParams(location.search);
    const legacyHash = location.hash.match(/^#analysis-(.+)$/)?.[1] || '';
    const legacyView = views.has(legacyHash) ? legacyHash : '';
    const view = safeSet(params.get('view') || legacyView, views);
    const phase = safeSet(params.get('phase'), phases) || ({
      diagram: 'model', 'trust-boundaries': 'model', stride: 'findings', linddun: 'findings',
      controls: 'action-plan', tests: 'action-plan', gaps: 'evidence',
    }[view] || '');
    const run = params.get('run') || '';
    const selected = params.get('selected') || '';
    const readMulti = (key, allowed) => [...new Set(params.getAll(key).flatMap(value => value.split(',')).filter(value => allowed.has(value)))];
    return {
      project: idPattern.test(params.get('id') || '') ? params.get('id') : '',
      run: idPattern.test(run) ? run : '',
      phase,
      view,
      filters: {
        framework: safeSet(params.get('f_framework'), frameworks),
        risk: safeSet(params.get('f_risk'), risks),
        stride: safeSet(params.get('f_stride'), categories),
        linddun: safeSet(params.get('f_linddun'), categories),
        priority: safeSet(params.get('f_priority'), priorities),
        findingFramework: readMulti('ff', frameworks),
        findingSeverity: readMulti('fs', risks),
        findingStatus: readMulti('fst', findingStatuses),
        findingState: readMulti('fstate', findingStates),
        findingInteraction: readMulti('fi', interactionStates),
      },
      query: (params.get('q') || '').slice(0, 160),
      sort: safeSet(params.get('sort'), findingSorts) || 'risk',
      action: {
        query: (params.get('aq') || '').slice(0, 160),
        types: readMulti('atype', actionTypes),
        priorities: readMulti('ap', actionPriorities),
        statuses: readMulti('ast', actionStatuses),
        executability: readMulti('aexec', actionExecutability),
        owner: (params.get('aowner') || '').slice(0, 80),
        sort: safeSet(params.get('asort'), actionSorts) || 'priority',
      },
      evidence: {
        query: (params.get('eq') || '').slice(0, 160),
        types: readMulti('etype', evidenceTypes),
        statuses: readMulti('est', evidenceStatuses),
        owner: (params.get('eowner') || '').slice(0, 80),
        sort: safeSet(params.get('esort'), evidenceSorts) || 'priority',
      },
      selection: selectionPattern.test(selected) ? selected : '',
    };
  }

  function update(patch = {}, { replace = true, hash } = {}) {
    const url = new URL(location.href);
    const current = read();
    const next = { ...current, ...patch, filters: { ...current.filters, ...(patch.filters || {}) } };
    const set = (key, value) => value ? url.searchParams.set(key, value) : url.searchParams.delete(key);
    set('id', idPattern.test(String(next.project || '')) ? next.project : '');
    set('run', idPattern.test(String(next.run || '')) ? next.run : '');
    set('phase', safeSet(next.phase || '', phases));
    set('view', safeSet(next.view || '', views));
    set('f_framework', safeSet(next.filters.framework || '', frameworks));
    set('f_risk', safeSet(next.filters.risk || '', risks));
    set('f_stride', safeSet(next.filters.stride || '', categories));
    set('f_linddun', safeSet(next.filters.linddun || '', categories));
    set('f_priority', safeSet(next.filters.priority || '', priorities));
    const setMulti = (key, values, allowed) => {
      url.searchParams.delete(key);
      [...new Set((Array.isArray(values) ? values : []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    };
    setMulti('ff', next.filters.findingFramework, frameworks);
    setMulti('fs', next.filters.findingSeverity, risks);
    setMulti('fst', next.filters.findingStatus, findingStatuses);
    setMulti('fstate', next.filters.findingState, findingStates);
    setMulti('fi', next.filters.findingInteraction, interactionStates);
    set('q', String(next.query || '').slice(0, 160));
    set('sort', safeSet(next.sort || '', findingSorts));
    const setActionMulti = (key, values, allowed) => {
      url.searchParams.delete(key);
      [...new Set((Array.isArray(values) ? values : []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    };
    setActionMulti('atype', next.action?.types, actionTypes);
    setActionMulti('ap', next.action?.priorities, actionPriorities);
    setActionMulti('ast', next.action?.statuses, actionStatuses);
    setActionMulti('aexec', next.action?.executability, actionExecutability);
    set('aq', String(next.action?.query || '').slice(0, 160));
    set('aowner', String(next.action?.owner || '').slice(0, 80));
    set('asort', safeSet(next.action?.sort || '', actionSorts));
    const setEvidenceMulti = (key, values, allowed) => {
      url.searchParams.delete(key);
      [...new Set((Array.isArray(values) ? values : []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    };
    setEvidenceMulti('etype', next.evidence?.types, evidenceTypes);
    setEvidenceMulti('est', next.evidence?.statuses, evidenceStatuses);
    set('eowner', String(next.evidence?.owner || '').slice(0, 80));
    set('esort', safeSet(next.evidence?.sort || '', evidenceSorts));
    set('eq', String(next.evidence?.query || '').slice(0, 160));
    set('selected', selectionPattern.test(next.selection || '') ? next.selection : '');
    if (hash !== undefined) url.hash = hash;
    const method = replace ? 'replaceState' : 'pushState';
    history[method](null, '', `${url.pathname}${url.search}${url.hash}`);
    return read();
  }

  function route(page, project, state = {}) {
    const url = new URL(`/${page}.html`, location.origin);
    if (idPattern.test(String(project || ''))) url.searchParams.set('id', project);
    for (const [key, value] of Object.entries({ run: state.run, phase: state.phase, view: state.view, selected: state.selection })) {
      if (value) url.searchParams.set(key, value);
    }
    Object.entries(state.filters || {}).forEach(([key, value]) => {
      const queryKey = `f_${key}`;
      if (['f_framework', 'f_risk', 'f_stride', 'f_linddun', 'f_priority'].includes(queryKey) && value) url.searchParams.set(queryKey, value);
    });
    const multiKeys = { findingFramework: ['ff', frameworks], findingSeverity: ['fs', risks], findingStatus: ['fst', findingStatuses], findingState: ['fstate', findingStates], findingInteraction: ['fi', interactionStates] };
    Object.entries(multiKeys).forEach(([name, [key, allowed]]) => {
      [...new Set((state.filters?.[name] || []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    });
    if (state.query) url.searchParams.set('q', String(state.query).slice(0, 160));
    if (safeSet(state.sort || '', findingSorts)) url.searchParams.set('sort', state.sort);
    const actionMultiKeys = { types: ['atype', actionTypes], priorities: ['ap', actionPriorities], statuses: ['ast', actionStatuses], executability: ['aexec', actionExecutability] };
    Object.entries(actionMultiKeys).forEach(([name, [key, allowed]]) => {
      [...new Set((state.action?.[name] || []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    });
    if (state.action?.query) url.searchParams.set('aq', String(state.action.query).slice(0, 160));
    if (state.action?.owner) url.searchParams.set('aowner', String(state.action.owner).slice(0, 80));
    if (safeSet(state.action?.sort || '', actionSorts)) url.searchParams.set('asort', state.action.sort);
    const evidenceMultiKeys = { types: ['etype', evidenceTypes], statuses: ['est', evidenceStatuses] };
    Object.entries(evidenceMultiKeys).forEach(([name, [key, allowed]]) => {
      [...new Set((state.evidence?.[name] || []).filter(value => allowed.has(value)))].forEach(value => url.searchParams.append(key, value));
    });
    if (state.evidence?.owner) url.searchParams.set('eowner', String(state.evidence.owner).slice(0, 80));
    if (safeSet(state.evidence?.sort || '', evidenceSorts)) url.searchParams.set('esort', state.evidence.sort);
    if (state.evidence?.query) url.searchParams.set('eq', String(state.evidence.query).slice(0, 160));
    return `${url.pathname}${url.search}`;
  }

  // Bind project-aware links before async project/report requests finish.
  function bindProjectLinks(project, state = {}) {
    if (!idPattern.test(String(project || ''))) return;
    const current = { ...read(), ...state };
    const targets = {
      'nav-analysis': ['analysis', { phase: '', view: '', selection: '' }],
      'back-analysis': ['analysis', { phase: '', view: '', selection: '' }],
      'nav-model': ['model', { phase: 'model', view: 'diagram', selection: '' }],
      'nav-findings': ['findings', { phase: 'findings', view: '', selection: '' }],
      'nav-action-plan': ['action-plan', { phase: 'action-plan', view: '', selection: '' }],
      'nav-evidence': ['evidence', { phase: 'evidence', view: '', selection: '' }],
      'nav-report': ['report', { phase: 'signoff', view: '' }],
      'btn-model-findings': ['findings', { phase: 'findings', view: '', selection: '' }],
      'btn-findings-model': ['model', { phase: 'model', view: 'diagram', selection: '' }],
      'btn-action-findings': ['findings', { phase: 'findings', view: '', selection: '' }],
    };
    Object.entries(targets).forEach(([id, [page, patch]]) => {
      const element = document.getElementById(id);
      if (element) element.href = route(page, project, { ...current, ...patch });
    });
  }

  window.UIState = { read, update, route, bindProjectLinks };
})();
