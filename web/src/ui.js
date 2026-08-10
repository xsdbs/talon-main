// --- UI PRIMITIVES ---
// Toasts, modals, confirm dialogs, popovers, lightbox. These replace the
// native alert()/confirm() calls the app used to make everywhere, which
// blocked the event loop and looked nothing like the rest of the product.

import { icon, escapeHTML } from './util.js';

/* ------------------------------------------------------------------ toasts */

const TOAST_ICONS = { ok: 'check', error: 'alert', warn: 'alert', info: 'info' };

/**
 * @param {string} message
 * @param {{type?: 'info'|'ok'|'error'|'warn', duration?: number,
 *          action?: {label: string, onClick: () => void}}} [opts]
 */
export function toast(message, opts = {}) {
  const host = document.getElementById('toasts');
  if (!host) return;

  const type = opts.type || 'info';
  const duration = opts.duration ?? (type === 'error' ? 5200 : 3200);

  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `
    <span class="toast-icon">${icon(TOAST_ICONS[type] || 'info', 17)}</span>
    <span class="toast-msg">${escapeHTML(message)}</span>
  `;

  if (opts.action) {
    const btn = document.createElement('button');
    btn.className = 'toast-action';
    btn.textContent = opts.action.label;
    btn.onclick = () => { opts.action.onClick(); dismiss(); };
    el.appendChild(btn);
  }

  let timer = null;
  const dismiss = () => {
    if (!el.isConnected) return;
    clearTimeout(timer);
    el.classList.add('leaving');
    el.addEventListener('animationend', () => el.remove(), { once: true });
    // Belt and braces: if the animation is suppressed by reduced motion the
    // animationend event may never fire.
    setTimeout(() => el.remove(), 400);
  };

  el.addEventListener('click', (e) => { if (!e.target.closest('.toast-action')) dismiss(); });
  host.appendChild(el);

  // Never let toasts stack past a readable number.
  while (host.children.length > 4) host.firstElementChild.remove();

  timer = setTimeout(dismiss, duration);
  return dismiss;
}

/* ------------------------------------------------------------------ modals */

let closeActiveModal = null;

/**
 * Renders a modal into the shared scrim host.
 * @param {{title: string, body: string, footer?: string, wide?: boolean,
 *          onMount?: (root: HTMLElement, close: () => void) => void,
 *          dismissible?: boolean}} spec
 * @returns {() => void} close
 */
export function openModal(spec) {
  const host = document.getElementById('modal-host');
  if (!host) return () => {};

  if (closeActiveModal) closeActiveModal();

  const dismissible = spec.dismissible !== false;

  host.innerHTML = `
    <div class="modal${spec.wide ? ' modal-wide' : ''}" role="dialog" aria-modal="true">
      <div class="modal-head">
        <h2 class="modal-title">${escapeHTML(spec.title)}</h2>
        ${dismissible ? `<button class="icon-btn" data-close aria-label="Close">${icon('close', 18)}</button>` : ''}
      </div>
      <div class="modal-body">${spec.body || ''}</div>
      ${spec.footer ? `<div class="modal-foot">${spec.footer}</div>` : ''}
    </div>
  `;
  host.hidden = false;

  const root = host.querySelector('.modal');

  const close = () => {
    host.hidden = true;
    host.innerHTML = '';
    document.removeEventListener('keydown', onKey, true);
    if (closeActiveModal === close) closeActiveModal = null;
  };
  closeActiveModal = close;

  function onKey(e) {
    if (e.key === 'Escape' && dismissible) {
      // Stop the app-wide Escape handlers (including panic-wipe's triple-Esc
      // counter) from also seeing this keystroke.
      e.stopPropagation();
      e.preventDefault();
      close();
    }
  }
  document.addEventListener('keydown', onKey, true);

  root.querySelectorAll('[data-close]').forEach((b) => { b.onclick = close; });
  if (dismissible) {
    host.onclick = (e) => { if (e.target === host) close(); };
  }

  if (spec.onMount) spec.onMount(root, close);

  // Focus the first sensible control so keyboard users land somewhere useful.
  requestAnimationFrame(() => {
    const target = root.querySelector('[data-autofocus], input:not([type=hidden]), textarea, button.btn-primary');
    if (target) target.focus();
  });

  return close;
}

export function closeModal() {
  if (closeActiveModal) closeActiveModal();
}

export function isModalOpen() {
  return !!closeActiveModal;
}

/**
 * Promise-based replacement for window.confirm.
 * @returns {Promise<boolean>}
 */
export function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; resolve(v); } };

    const close = openModal({
      title,
      body: `<p style="color:var(--fg-muted);line-height:1.6">${escapeHTML(message)}</p>`,
      footer: `
        <button class="btn" data-cancel>${escapeHTML(cancelLabel)}</button>
        <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-confirm>${escapeHTML(confirmLabel)}</button>
      `,
      onMount(root, closeFn) {
        root.querySelector('[data-cancel]').onclick = () => { finish(false); closeFn(); };
        root.querySelector('[data-confirm]').onclick = () => { finish(true); closeFn(); };
        root.querySelector('[data-confirm]').focus();
      }
    });

    // Dismissing via Escape / backdrop counts as "no".
    const host = document.getElementById('modal-host');
    const observer = new MutationObserver(() => {
      if (host.hidden) { finish(false); observer.disconnect(); }
    });
    observer.observe(host, { attributes: true, attributeFilter: ['hidden'] });
    void close;
  });
}

/** Single-field prompt. Resolves to the trimmed string, or null if cancelled. */
export function promptDialog({ title, label, value = '', placeholder = '', confirmLabel = 'Save', multiline = false }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; resolve(v); } };

    openModal({
      title,
      body: `
        <div class="field">
          <label class="field-label" for="prompt-field">${escapeHTML(label)}</label>
          ${multiline
            ? `<textarea class="textarea" id="prompt-field" placeholder="${escapeHTML(placeholder)}" data-autofocus>${escapeHTML(value)}</textarea>`
            : `<input class="input" id="prompt-field" value="${escapeHTML(value)}" placeholder="${escapeHTML(placeholder)}" data-autofocus>`}
        </div>
      `,
      footer: `
        <button class="btn" data-cancel>Cancel</button>
        <button class="btn btn-primary" data-ok>${escapeHTML(confirmLabel)}</button>
      `,
      onMount(root, close) {
        const field = root.querySelector('#prompt-field');
        const submit = () => { finish(field.value.trim()); close(); };
        root.querySelector('[data-ok]').onclick = submit;
        root.querySelector('[data-cancel]').onclick = () => { finish(null); close(); };
        if (!multiline) {
          field.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } };
        }
      }
    });

    const host = document.getElementById('modal-host');
    const observer = new MutationObserver(() => {
      if (host.hidden) { finish(null); observer.disconnect(); }
    });
    observer.observe(host, { attributes: true, attributeFilter: ['hidden'] });
  });
}

/* ---------------------------------------------------------------- popovers */

let activePopover = null;

/**
 * Anchors a floating element near a trigger, flipping it when it would spill
 * off-screen, and closes it on outside click / Escape / scroll.
 */
export function openPopover(anchorEl, html, { className = '', onMount, placement = 'auto' } = {}) {
  closePopover();

  const pop = document.createElement('div');
  pop.className = `popover ${className}`;
  pop.innerHTML = html;
  document.body.appendChild(pop);

  const rect = anchorEl.getBoundingClientRect();
  const pw = pop.offsetWidth;
  const ph = pop.offsetHeight;
  const margin = 8;

  let top = rect.bottom + margin;
  let flipped = false;
  if (placement === 'up' || top + ph > window.innerHeight - margin) {
    top = rect.top - ph - margin;
    flipped = true;
  }
  if (top < margin) top = margin;

  let left = rect.left;
  if (left + pw > window.innerWidth - margin) left = window.innerWidth - pw - margin;
  if (left < margin) left = margin;

  pop.style.position = 'fixed';
  pop.style.top = `${top}px`;
  pop.style.left = `${left}px`;
  if (flipped) pop.classList.add('up');

  const close = () => {
    if (!pop.isConnected) return;
    pop.remove();
    document.removeEventListener('mousedown', onOutside, true);
    document.removeEventListener('keydown', onKey, true);
    window.removeEventListener('resize', close);
    if (activePopover === close) activePopover = null;
  };

  function onOutside(e) {
    if (!pop.contains(e.target) && !anchorEl.contains(e.target)) close();
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); close(); }
  }

  // Deferred so the click that opened it doesn't immediately close it.
  setTimeout(() => {
    document.addEventListener('mousedown', onOutside, true);
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', close, { once: true });
  }, 0);

  activePopover = close;
  if (onMount) onMount(pop, close);
  return close;
}

export function closePopover() {
  if (activePopover) activePopover();
}

/* --------------------------------------------------------------- lightbox */

let lightboxUrl = null;
let lightboxName = 'image';

export function openLightbox(url, caption = '', filename = 'image') {
  const box = document.getElementById('lightbox');
  const img = document.getElementById('lightbox-img');
  const cap = document.getElementById('lightbox-cap');
  if (!box || !img) return;

  lightboxUrl = url;
  lightboxName = filename;
  img.src = url;
  img.alt = caption || filename;
  if (cap) cap.textContent = caption;
  box.hidden = false;
}

export function closeLightbox() {
  const box = document.getElementById('lightbox');
  if (box) box.hidden = true;
}

export function initLightbox() {
  const box = document.getElementById('lightbox');
  if (!box) return;

  document.getElementById('lightbox-close').onclick = closeLightbox;
  document.getElementById('lightbox-download').onclick = () => {
    if (!lightboxUrl) return;
    const a = document.createElement('a');
    a.href = lightboxUrl;
    a.download = lightboxName;
    a.click();
  };
  box.onclick = (e) => { if (e.target === box || e.target.tagName === 'IMG') closeLightbox(); };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !box.hidden) { e.stopPropagation(); closeLightbox(); }
  }, true);
}

/* ------------------------------------------------------------- net banner */

let netBannerTimer = null;

export function showNetBanner(text, kind = 'offline', autoHideMs = 0) {
  const el = document.getElementById('net-banner');
  const label = document.getElementById('net-banner-text');
  if (!el || !label) return;

  clearTimeout(netBannerTimer);
  label.textContent = text;
  el.classList.remove('offline', 'online');
  el.classList.add(kind, 'show');

  if (autoHideMs) netBannerTimer = setTimeout(hideNetBanner, autoHideMs);
}

export function hideNetBanner() {
  const el = document.getElementById('net-banner');
  if (el) el.classList.remove('show');
}
