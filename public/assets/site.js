document.querySelectorAll('.menu-toggle').forEach(button => {
  const nav = document.getElementById(button.getAttribute('aria-controls'));
  button.addEventListener('click', () => {
    const open = button.getAttribute('aria-expanded') !== 'true';
    button.setAttribute('aria-expanded', String(open));
    nav.classList.toggle('is-open', open);
    button.textContent = open ? 'Close' : 'Menu';
  });
  nav.addEventListener('click', event => {
    if (event.target.closest('a')) {
      button.setAttribute('aria-expanded', 'false'); nav.classList.remove('is-open'); button.textContent = 'Menu';
    }
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && button.getAttribute('aria-expanded') === 'true') { button.click(); button.focus(); }
  });
});
document.querySelectorAll('[role=tablist]').forEach(list => {
  const tabs = [...list.querySelectorAll('[role=tab]')];
  function activate(tab, focus = false) {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected)); item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(tab));
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) { event.preventDefault(); activate(tabs[next], true); }
    });
  });
});
document.querySelectorAll('.copy-button').forEach(button => button.addEventListener('click', async () => {
  const code = button.parentElement.querySelector('code');
  try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Copied'; }
  catch { button.textContent = 'Select text to copy'; const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(code); selection.removeAllRanges(); selection.addRange(range); }
  window.setTimeout(() => { button.textContent = 'Copy'; }, 2200);
}));
const search = document.querySelector('[data-tool-search]');
if (search) {
  let category = 'all';
  const rows = [...document.querySelectorAll('[data-tool-category]')];
  const filters = [...document.querySelectorAll('[data-filter]')];
  const update = () => {
    const query = search.value.trim().toLowerCase(); let count = 0;
    rows.forEach(row => { row.hidden = !(category === 'all' || row.dataset.toolCategory === category) || !row.textContent.toLowerCase().includes(query); if (!row.hidden) count++; });
    document.querySelector('[data-result-count]').textContent = `${count} ${count === 1 ? 'tool' : 'tools'} shown`;
    document.querySelector('[data-empty]').hidden = count !== 0;
  };
  filters.forEach(button => button.addEventListener('click', () => { category = button.dataset.filter; filters.forEach(item => item.setAttribute('aria-pressed', String(item === button))); update(); }));
  search.addEventListener('input', update); update();
}
