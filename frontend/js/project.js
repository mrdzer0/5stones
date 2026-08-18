/**
 * New Project Wizard
 */
let currentStep = 1;
const totalSteps = 4;
let tagInputs = {};
const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const ARTIFACT_ACCEPT = {
  prd: '.pdf,.docx,.md,.markdown,.txt',
  openapi: '.json,.yaml,.yml',
  postman: '.json',
  markdown: '.md,.markdown,.txt',
  database_schema: '.sql,.txt',
  csv: '.csv,.txt',
  har: '.har,.json',
  text: '.txt,.md,.markdown',
};

document.addEventListener('DOMContentLoaded', () => {
  // Init tag inputs
  tagInputs.actors = initTagInput('actors-wrap', 'actors-input');
  tagInputs.entryPoints = initTagInput('entry-points-wrap', 'entry-points-input');
  tagInputs.criticalActions = initTagInput('critical-actions-wrap', 'critical-actions-input');
  tagInputs.dataInvolved = initTagInput('data-involved-wrap', 'data-involved-input');
  tagInputs.externalSystems = initTagInput('external-systems-wrap', 'external-systems-input');
  tagInputs.existingControls = initTagInput('existing-controls-wrap', 'existing-controls-input');

  // Artifact type toggle
  document.getElementById('artifact-type').addEventListener('change', (e) => {
    updateArtifactInputs(e.target.value);
  });
  document.getElementById('artifact-file')?.addEventListener('change', (e) => {
    updateProjectArtifactSelection(e.target.files?.[0]);
  });

  // Navigation
  document.getElementById('btn-next').addEventListener('click', handleNext);
  document.getElementById('btn-prev').addEventListener('click', handlePrev);

  updateStepUI();
});

function updateStepUI() {
  for (let i = 1; i <= totalSteps; i++) {
    const el = document.getElementById(`step-${i}`);
    const ind = document.getElementById(`step-indicator-${i}`);
    if (el) el.style.display = i === currentStep ? 'block' : 'none';
    if (ind) {
      ind.classList.remove('active', 'done');
      if (i === currentStep) ind.classList.add('active');
      if (i < currentStep) ind.classList.add('done');
    }
  }
  document.getElementById('step-counter').textContent = `Step ${currentStep} of ${totalSteps}`;
  document.getElementById('btn-prev').style.visibility = currentStep === 1 ? 'hidden' : 'visible';

  const nextBtn = document.getElementById('btn-next');
  if (currentStep === totalSteps) {
    nextBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Create Project`;
  } else {
    nextBtn.innerHTML = `Next <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>`;
  }
}

function updateArtifactInputs(type) {
  const fileGroup = document.getElementById('artifact-file-group');
  const fileInput = document.getElementById('artifact-file');
  const hint = document.getElementById('artifact-file-hint');
  const show = Boolean(type);
  if (fileGroup) fileGroup.style.display = show ? 'block' : 'none';
  if (fileInput) {
    fileInput.value = '';
    fileInput.accept = ARTIFACT_ACCEPT[type] || '';
  }
  if (hint) {
    hint.textContent = show
      ? `Max 5 MB. Allowed: ${ARTIFACT_ACCEPT[type] || 'selected artifact formats'}. Upload only data needed for threat modeling.`
      : 'Max 5 MB. Allowed formats depend on artifact type.';
  }
  updateProjectArtifactSelection(null);
}

function formatProjectArtifactBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function updateProjectArtifactSelection(file) {
  const status = document.getElementById('artifact-file-status');
  if (!status) return;
  status.classList.toggle('is-ready', Boolean(file));
  if (!file) {
    status.textContent = 'Choose a file to inspect before creating the project.';
    return;
  }
  status.textContent = file.size > MAX_ARTIFACT_BYTES
    ? `${file.name} · ${formatProjectArtifactBytes(file.size)} · exceeds the 5 MB limit`
    : `${file.name} · ${formatProjectArtifactBytes(file.size)} · ready to parse`;
}

function setProjectArtifactResult(kind, html) {
  const result = document.getElementById('project-artifact-result');
  if (!result) return;
  result.className = `artifact-import-result is-visible is-${kind}`;
  result.innerHTML = html;
}

function validateStep(step) {
  if (step === 1) {
    const name = document.getElementById('project-name').value.trim();
    const desc = document.getElementById('project-desc').value.trim();
    if (!name) { showToast('Project name is required', 'warn'); return false; }
    if (!desc) { showToast('Description is required', 'warn'); return false; }
  }
  if (step === 2) {
    if (!tagInputs.actors?.getTags().length) {
      showToast('Add at least one actor', 'warn'); return false;
    }
  }
  if (step === 4) {
    const type = document.getElementById('artifact-type').value;
    const file = document.getElementById('artifact-file')?.files?.[0];
    if (type && !file) {
      showToast('Choose an artifact file or select manual input only', 'warn');
      return false;
    }
  }
  return true;
}

async function handleNext() {
  if (!validateStep(currentStep)) return;

  if (currentStep < totalSteps) {
    currentStep++;
    updateStepUI();
    return;
  }

  // Final step — create project
  await createProject();
}

function handlePrev() {
  if (currentStep > 1) {
    currentStep--;
    updateStepUI();
  }
}

async function createProject() {
  const btn = document.getElementById('btn-next');
  btn.disabled = true;
  btn.innerHTML = `<div class="loading-spinner"></div> Creating…`;
  btn.setAttribute('aria-busy', 'true');

  const payload = {
    name: document.getElementById('project-name').value.trim(),
    description: document.getElementById('project-desc').value.trim(),
    environment: document.getElementById('project-env').value,
    data_policy: document.getElementById('project-policy').value,
    actors: tagInputs.actors?.getTags() || [],
    entry_points: tagInputs.entryPoints?.getTags() || [],
    auth_method: document.getElementById('auth-method').value.trim(),
    critical_actions: tagInputs.criticalActions?.getTags() || [],
    data_involved: tagInputs.dataInvolved?.getTags() || [],
    external_systems: tagInputs.externalSystems?.getTags() || [],
    existing_controls: tagInputs.existingControls?.getTags() || [],
  };

  try {
    const project = await API.projects.create(payload);

    // Upload artifact if provided.
    const artifactType = document.getElementById('artifact-type').value;
    const artifactFile = document.getElementById('artifact-file')?.files?.[0];
    if (artifactType && artifactFile) {
      try {
        if (artifactFile.size > MAX_ARTIFACT_BYTES) throw new Error('File exceeds 5 MB limit');
        btn.innerHTML = `<div class="loading-spinner"></div> Parsing artifact…`;
        setProjectArtifactResult('working', `
          <div class="artifact-result-title">Project created · parsing ${escHtml(artifactFile.name)}…</div>
          <div>The complete file is being normalized and added to the project context.</div>
        `);
        const response = await API.artifacts.uploadFile(project.project_id, artifactType, artifactFile);
        const inventory = response.reconciliation || {};
        const parsedStats = response.parsed?.stats || {};
        setProjectArtifactResult('success', `
          <div class="artifact-result-title">Project and artifact are ready</div>
          <div>${escHtml(response.message || 'Structured context added successfully.')}</div>
          <div class="artifact-result-metrics">
            <div class="artifact-result-metric"><strong>${parsedStats.operation_count || 0}</strong><span>operations parsed</span></div>
            <div class="artifact-result-metric"><strong>${inventory.operation_count || parsedStats.operation_count || 0}</strong><span>canonical operations</span></div>
          </div>
        `);
        showToast('Project created and artifact reconciled', 'success');
      } catch (err) {
        setProjectArtifactResult('error', `
          <div class="artifact-result-title">Project created, but the artifact needs attention</div>
          <div>${escHtml(err.message)}</div>
          <div style="margin-top:6px;">You can retry from the Add Artifact panel on the project page.</div>
        `);
        showToast('Project created; retry the artifact from the project page', 'warn');
        setTimeout(() => {
          window.location.href = `/analysis.html?id=${project.project_id}&artifact_error=${encodeURIComponent(err.message)}`;
        }, 1400);
        return;
      }
    } else {
      showToast('Project created!', 'success');
    }

    setTimeout(() => {
      window.location.href = `/analysis.html?id=${project.project_id}`;
    }, 900);

  } catch (err) {
    showToast('Error: ' + err.message, 'error');
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    updateStepUI();
  }
}
