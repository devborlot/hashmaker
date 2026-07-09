const PARAMS = {
  bcrypt: [{ key: 'bcrypt_cost', label: 'cost', min: 4, max: 31, value: 12 }],
  pbkdf2_sha256: [{ key: 'pbkdf2_iterations', label: 'iter', min: 1000, max: 10000000, step: 1000, value: 100000 }],
  wordpress: [{ key: 'wordpress_log2', label: 'log2', min: 4, max: 31, value: 8 }],
};

const $ = (sel) => document.querySelector(sel);
const rows = new Map();
let password = '';
let debounceTimer = null;

async function init() {
  const res = await fetch('/api/algorithms');
  const { algorithms } = await res.json();
  renderRows(algorithms);
  bindPassword();
}

function renderRows(algorithms) {
  const container = $('#rows');
  container.innerHTML = algorithms
    .map((algo) => {
      const params = PARAMS[algo.id];
      const cfgHtml = params
        ? params
            .map(
              (p) => `
          <span class="cfg-k">${p.label}</span>
          <input class="cfg-v" type="number" data-param="${p.key}"
            min="${p.min}" max="${p.max}" ${p.step ? `step="${p.step}"` : ''} value="${p.value}">`
            )
            .join('')
        : '<span class="cfg-empty">·</span>';

      return `
        <div class="row" data-id="${algo.id}">
          <div class="row-head">
            <span class="name">${algo.label.toLowerCase()}</span>
            <span class="cfg">${cfgHtml}</span>
            <button type="button" class="cp" disabled>cp</button>
          </div>
          <div class="out empty">—</div>
        </div>`;
    })
    .join('');

  container.querySelectorAll('.row').forEach((el) => {
    const id = el.dataset.id;
    rows.set(id, {
      el,
      outEl: el.querySelector('.out'),
      cpBtn: el.querySelector('.cp'),
      hash: '',
      seq: 0,
    });

    el.querySelector('.cp').addEventListener('click', () => copy(id));

    el.querySelectorAll('.cfg-v').forEach((input) => {
      input.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => hashOne(id), 300);
      });
    });
  });
}

function bindPassword() {
  const input = $('#password');

  input.addEventListener('input', () => {
    password = input.value;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(refreshAll, 200);
  });

  $('#toggle-visibility').addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    $('#toggle-visibility').textContent = show ? 'hide' : 'show';
  });
}

function refreshAll() {
  if (!password) {
    rows.forEach((_, id) => setEmpty(id));
    return;
  }
  rows.forEach((_, id) => hashOne(id));
}

function setEmpty(id) {
  const row = rows.get(id);
  row.hash = '';
  row.outEl.textContent = '—';
  row.outEl.className = 'out empty';
  row.cpBtn.disabled = true;
}

function getOptions(id) {
  const options = {};
  rows.get(id).el.querySelectorAll('[data-param]').forEach((input) => {
    options[input.dataset.param] = parseInt(input.value, 10) || 0;
  });
  return options;
}

async function hashOne(id) {
  const row = rows.get(id);
  const seq = ++row.seq;

  if (!password) {
    setEmpty(id);
    return;
  }

  row.outEl.textContent = '…';
  row.outEl.className = 'out loading';
  row.cpBtn.disabled = true;

  try {
    const res = await fetch('/api/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        password,
        algorithms: [id],
        options: getOptions(id),
      }),
    });

    const data = await res.json();
    if (seq !== row.seq) return;

    if (!res.ok) {
      row.outEl.textContent = data.error || 'err';
      row.outEl.className = 'out error';
      return;
    }

    const result = data.results[0];
    const error = data.errors[0];

    if (result) {
      row.hash = result.hash;
      row.outEl.textContent = result.hash;
      row.outEl.className = 'out';
      row.cpBtn.disabled = false;
    } else {
      row.hash = '';
      row.outEl.textContent = error?.error || 'err';
      row.outEl.className = 'out error';
    }
  } catch {
    if (seq !== row.seq) return;
    row.outEl.textContent = 'req fail';
    row.outEl.className = 'out error';
  }
}

async function copy(id) {
  const row = rows.get(id);
  if (!row.hash) return;
  try {
    await navigator.clipboard.writeText(row.hash);
    row.cpBtn.textContent = 'ok';
    row.cpBtn.classList.add('ok');
    setTimeout(() => {
      row.cpBtn.textContent = 'cp';
      row.cpBtn.classList.remove('ok');
    }, 800);
  } catch { /* ignore */ }
}

init();
