/* Warehouse Finder — vyhledávání a detail položky (CZ + EN popis) */

const MAX_RESULTS = 250;
const SNIPPET_RADIUS = 70;

const els = {
  search: document.getElementById('searchInput'),
  body: document.getElementById('resultsBody'),
  meta: document.getElementById('resultsMeta'),
  count: document.getElementById('resultCount'),
  modalOverlay: document.getElementById('modalOverlay'),
  modal: document.getElementById('modalBox'),
};

let CATALOG = [];

function normalize(str) {
  return (str || '')
    .toString()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function escapeHtml(str) {
  return (str || '')
    .toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function fetchJson(url) {
  try {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function loadCatalog() {
  els.meta.textContent = 'Načítání katalogu…';
  try {
    const [raw, popisEn] = await Promise.all([
      fetchJson('katalog.json'),
      fetchJson('popis_en.json'),
    ]);

    if (!raw) throw new Error('katalog.json se nepodařilo načíst');
    const enMap = popisEn || {};

    CATALOG = raw.map(item => {
      const popisEnText = enMap[item.kod] || '';
      return {
        kod: item.kod ?? '',
        popis: item.popis ?? '',
        popisEn: popisEnText,
        zasoby: Number(item.zasoby) || 0,
        _kodN: normalize(item.kod),
        _popisN: normalize(item.popis),
        _popisEnN: normalize(popisEnText),
      };
    });

    els.count.innerHTML = `<strong>${CATALOG.length}</strong> položek celkem`;
    render();
  } catch (e) {
    els.meta.textContent = 'Katalog se nepodařilo načíst.';
    els.body.innerHTML = `<tr><td colspan="3" class="empty">Nepodařilo se načíst katalog.json. Zkontrolujte, že soubor existuje ve stejné složce jako index.html.</td></tr>`;
    console.error(e);
  }
}

function getSnippet(text, words) {
  if (!text) return '';
  if (!words.length) {
    return text.length > 160 ? escapeHtml(text.slice(0, 160)) + '…' : escapeHtml(text);
  }
  const norm = normalize(text);
  let firstIdx = -1;
  for (const w of words) {
    const idx = norm.indexOf(w);
    if (idx !== -1 && (firstIdx === -1 || idx < firstIdx)) firstIdx = idx;
  }
  if (firstIdx === -1) {
    return text.length > 160 ? escapeHtml(text.slice(0, 160)) + '…' : escapeHtml(text);
  }
  const start = Math.max(0, firstIdx - SNIPPET_RADIUS);
  const end = Math.min(text.length, firstIdx + SNIPPET_RADIUS);
  let snippet = text.slice(start, end);
  if (start > 0) snippet = '…' + snippet;
  if (end < text.length) snippet = snippet + '…';
  return highlight(snippet, words);
}

function highlight(text, words) {
  if (!text) return '';
  if (!words.length) return escapeHtml(text);
  const norm = normalize(text);
  let result = '';
  let i = 0;
  while (i < text.length) {
    let matchLen = 0;
    for (const w of words) {
      if (norm.startsWith(w, i) && w.length > matchLen) matchLen = w.length;
    }
    if (matchLen > 0) {
      result += '<mark>' + escapeHtml(text.slice(i, i + matchLen)) + '</mark>';
      i += matchLen;
    } else {
      result += escapeHtml(text[i]);
      i += 1;
    }
  }
  return result;
}

function matchesQuery(item, words) {
  if (!words.length) return true;
  const haystack = item._kodN + ' ' + item._popisN + ' ' + item._popisEnN;
  return words.every(w => haystack.includes(w));
}

function score(item, words) {
  if (!words.length) return 0;
  let s = 0;
  for (const w of words) {
    if (item._kodN.includes(w)) s -= 100;
    if (item._popisN.startsWith(w)) s -= 20;
    if (item._popisEnN.startsWith(w)) s -= 10;
  }
  return s;
}

function render() {
  const query = els.search.value.trim();
  const words = normalize(query).split(/\s+/).filter(Boolean);

  let results = CATALOG.filter(item => matchesQuery(item, words));

  if (words.length) {
    results = results
      .map(item => ({ item, s: score(item, words) }))
      .sort((a, b) => a.s - b.s || a.item.kod.localeCompare(b.item.kod, 'cs'))
      .map(x => x.item);
  } else {
    results = [...results].sort((a, b) => a.kod.localeCompare(b.kod, 'cs'));
  }

  const total = results.length;
  const shown = results.slice(0, MAX_RESULTS);

  if (total === 0) {
    els.meta.innerHTML = 'Nic nenalezeno — zkuste jiný výraz.';
    els.body.innerHTML = `<tr><td colspan="3" class="empty">Žádné položky neodpovídají hledání.</td></tr>`;
  } else {
    els.meta.innerHTML = total > MAX_RESULTS
      ? `Zobrazeno <strong>${shown.length}</strong> z <strong>${total}</strong> výsledků — upřesněte hledání pro zúžení výpisu`
      : `Nalezeno <strong>${total}</strong> ${total === 1 ? 'položka' : (total < 5 ? 'položky' : 'položek')}`;

    els.body.innerHTML = shown.map(item => rowHtml(item, words)).join('');
  }

  attachRowHandlers(words);
}

function rowHtml(item, words) {
  const lowStock = item.zasoby <= 0;
  const rowClass = ['row'];
  if (lowStock) rowClass.push('out-of-stock');

  const enLine = item.popisEn
    ? `<span class="popis-en">${getSnippet(item.popisEn, words)}</span>`
    : '';

  return `
    <tr class="${rowClass.join(' ')}" data-kod="${escapeHtml(item.kod)}">
      <td class="kod" data-label="Kód">${highlight(item.kod, words)}</td>
      <td class="popis" data-label="Popis">${getSnippet(item.popis, words)}${enLine}</td>
      <td class="zasoby" data-label="Zásoby">${item.zasoby}</td>
    </tr>
  `;
}

function attachRowHandlers(words) {
  els.body.querySelectorAll('tr[data-kod]').forEach(tr => {
    tr.addEventListener('click', () => {
      const kod = tr.dataset.kod;
      const item = CATALOG.find(i => i.kod === kod);
      if (item) openModal(item, words);
    });
  });
}

function openModal(item, words) {
  const enBlock = item.popisEn
    ? `<div class="popis-en">${highlight(item.popisEn, words)}</div>`
    : '';

  els.modal.innerHTML = `
    <div class="detail-top">
      <div class="kod">${highlight(item.kod, words)}</div>
      <button class="close-btn" id="closeModalBtn">Zavřít</button>
    </div>
    <div class="popis">${highlight(item.popis, words)}</div>
    ${enBlock}
    <div class="meta-row">
      <div class="bball">
        <div class="stack">
          <span class="label">Skladové zásoby</span>
          <span class="num">${item.zasoby}<span class="unit">ks</span></span>
          <span class="bball-note">aktuální množství nutné ověřit v Business Central</span>
        </div>
      </div>
    </div>
  `;
  els.modalOverlay.classList.add('open');
  document.getElementById('closeModalBtn').addEventListener('click', closeModal);
}

function closeModal() {
  els.modalOverlay.classList.remove('open');
  els.modal.innerHTML = '';
}

els.modalOverlay.addEventListener('click', (e) => {
  if (e.target === els.modalOverlay) closeModal();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && els.modalOverlay.classList.contains('open')) closeModal();
});

let debounceTimer;
els.search.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(render, 120);
});

loadCatalog();
