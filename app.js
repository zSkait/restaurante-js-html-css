/* =====================================================================
   CAFÉ AROMA - Sistema de gestión
   app.js - datos, seguridad, autenticación, navegación y vistas
   ===================================================================== */

/* ===================== Constantes ===================== */
const DB_KEY = 'cafeRestDB';
const SESSION_KEY = 'cafeRestSession';
const ROLES = ['admin', 'mesero', 'cocina', 'despacho'];

const DISH_EMOJIS = ['☕', '🥐', '🍰', '🥪', '🧁', '🍫', '🥛', '🍩'];

/* ===================== Datos iniciales (semilla) ===================== */
function seedData() {
  return {
    users: [
      { id: '1', username: 'admin', passwordHash: null, plainSeed: 'admin123', role: 'admin' },
      { id: '2', username: 'mesero', passwordHash: null, plainSeed: 'mesero123', role: 'mesero' },
      { id: '3', username: 'cocina', passwordHash: null, plainSeed: 'cocina123', role: 'cocina' },
      { id: '4', username: 'despacho', passwordHash: null, plainSeed: 'despacho123', role: 'despacho' }
    ],
    tables: [
      { id: '1', name: 'Mesa 1', capacity: 2, zone: 'Interior', state: 'available' },
      { id: '2', name: 'Mesa 2', capacity: 4, zone: 'Interior', state: 'available' },
      { id: '3', name: 'Mesa 3', capacity: 4, zone: 'Terraza', state: 'available' },
      { id: '4', name: 'Mesa 4', capacity: 2, zone: 'Barra', state: 'available' },
      { id: '5', name: 'Mesa 5', capacity: 6, zone: 'Terraza', state: 'available' },
      { id: '6', name: 'Mesa 6', capacity: 4, zone: 'Interior', state: 'available' },
      { id: '7', name: 'Mesa 7', capacity: 2, zone: 'Barra', state: 'available' },
      { id: '8', name: 'Mesa 8', capacity: 6, zone: 'Terraza', state: 'available' }
    ],
    reservations: [],
    dishes: [
      { id: '1', name: 'Café Americano', description: 'Café negro filtrado, intenso y aromático', price: 4500, emoji: '☕' },
      { id: '2', name: 'Cappuccino', description: 'Espresso con leche cremosa vaporizada', price: 5500, emoji: '☕' },
      { id: '3', name: 'Latte Vainilla', description: 'Espresso suave con leche y vainilla', price: 6000, emoji: '🥛' },
      { id: '4', name: 'Croissant de Mantequilla', description: 'Hojaldre artesanal recién horneado', price: 4000, emoji: '🥐' },
      { id: '5', name: 'Cheesecake de Fresa', description: 'Tarta cremosa con salsa de fresa', price: 7500, emoji: '🍰' },
      { id: '6', name: 'Sandwich Club', description: 'Pollo, tocineta, lechuga y tomate', price: 9000, emoji: '🥪' },
      { id: '7', name: 'Muffin de Arándanos', description: 'Esponjoso, con arándanos frescos', price: 4500, emoji: '🧁' },
      { id: '8', name: 'Brownie con Helado', description: 'Brownie tibio con bola de helado', price: 6500, emoji: '🍫' }
    ],
    orders: [],
    dispatches: []
  };
}

/* ===================== Seguridad ===================== */
const Security = {
  // Hashea texto con SHA-256 usando SubtleCrypto
  async sha256(text) {
    const enc = new TextEncoder().encode(text);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Ofuscación básica adicional sobre el hash antes de guardarlo
  obfuscate(str) {
    return btoa(unescape(encodeURIComponent(str)));
  },
  deobfuscate(str) {
    try { return decodeURIComponent(escape(atob(str))); } catch { return ''; }
  },

  async hashPassword(plain) {
    const hash = await this.sha256(plain);
    return this.obfuscate(hash);
  },

  async verifyPassword(plain, storedObfuscated) {
    const candidate = await this.hashPassword(plain);
    return candidate === storedObfuscated;
  },

  // Sanitiza texto antes de insertarlo en el DOM
  sanitize(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  },

  randomCaptcha() {
    const a = Math.floor(Math.random() * 8) + 1;
    const b = Math.floor(Math.random() * 8) + 1;
    return { a, b, answer: a + b };
  }
};

/* ===================== Base de datos (localStorage) ===================== */
const Store = {
  load() {
    const raw = localStorage.getItem(DB_KEY);
    if (!raw) return null;
    try { return JSON.parse(this.deobfWrap(raw)); } catch { return null; }
  },
  save(db) {
    localStorage.setItem(DB_KEY, this.obfWrap(JSON.stringify(db)));
  },
  // Envoltura simple de ofuscación para todo el bloque
  obfWrap(json) { return btoa(unescape(encodeURIComponent(json))); },
  deobfWrap(b64) { return decodeURIComponent(escape(atob(b64))); },

  async init() {
    let db = this.load();
    if (!db) {
      db = seedData();
      for (const u of db.users) {
        u.passwordHash = await Security.hashPassword(u.plainSeed);
        delete u.plainSeed;
      }
      this.save(db);
    }
    return db;
  },

  async reset() {
    const db = seedData();
    for (const u of db.users) {
      u.passwordHash = await Security.hashPassword(u.plainSeed);
      delete u.plainSeed;
    }
    this.save(db);
    return db;
  },

  genId(list) {
    const max = list.reduce((m, x) => Math.max(m, parseInt(x.id) || 0), 0);
    return String(max + 1);
  }
};

let DB = null; // cache en memoria de la sesión actual

/* ===================== Sesión / Autenticación ===================== */
const Auth = {
  getSession() {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  },

  setSession(user) {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ username: user.username, role: user.role, active: true }));
  },

  clearSession() {
    localStorage.removeItem(SESSION_KEY);
  },

  // Verifica que la sesión siga siendo válida contra los datos reales de usuarios
  currentUser() {
    const session = this.getSession();
    if (!session || !session.active) return null;
    const user = DB.users.find(u => u.username === session.username);
    if (!user) { this.clearSession(); return null; }
    // Si el rol de la sesión no coincide con el real, se invalida (anti-manipulación)
    if (user.role !== session.role) { this.clearSession(); return null; }
    return user;
  },

  async login(username, password) {
    const user = DB.users.find(u => u.username === username);
    if (!user) return { ok: false, msg: 'Usuario o contraseña incorrectos.' };
    const valid = await Security.verifyPassword(password, user.passwordHash);
    if (!valid) return { ok: false, msg: 'Usuario o contraseña incorrectos.' };
    this.setSession(user);
    return { ok: true, user };
  },

  logout() {
    this.clearSession();
    // replace() no deja el dashboard en el historial: "adelante" no puede volver a él
    window.location.replace('index.html');
  },

  requireAuth() {
    const user = this.currentUser();
    if (!user) { window.location.replace('index.html'); return null; }
    return user;
  }
};

/* Evita que el botón "atrás/adelante" muestre una página que ya no corresponde
   a la sesión actual (login <-> dashboard). Se apoya en:
   1) location.replace() al navegar (no crea entradas nuevas en el historial)
   2) revalidar la sesión cuando la página se restaura desde el bfcache */
function guardHistoryNavigation(pageType) {
  const check = () => {
    const loggedIn = !!Auth.currentUser();
    if (pageType === 'login' && loggedIn) window.location.replace('dashboard.html');
    if (pageType === 'dashboard' && !loggedIn) window.location.replace('index.html');
  };
  window.addEventListener('pageshow', (e) => { if (e.persisted) check(); });
  window.addEventListener('popstate', check);
  check();
}

/* ===================== Utilidades UI ===================== */
const UI = {
  toast(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3200);
  },

  money(n) {
    return '$' + Number(n || 0).toLocaleString('es-CO');
  },

  today() {
    return new Date().toISOString().slice(0, 10);
  },

  confirmModal(title, message) {
    return new Promise(resolve => {
      const root = document.getElementById('modalRoot');
      root.innerHTML = `
        <div class="modal-overlay">
          <div class="modal-box" style="max-width:400px">
            <div class="modal-head"><h3>${Security.sanitize(title)}</h3></div>
            <p class="text-muted" style="font-size:.9rem;color:#5c4c3f">${Security.sanitize(message)}</p>
            <div class="modal-actions">
              <button class="btn btn-ghost" id="cfCancel">Cancelar</button>
              <button class="btn btn-danger" id="cfOk">Confirmar</button>
            </div>
          </div>
        </div>`;
      document.getElementById('cfCancel').onclick = () => { root.innerHTML = ''; resolve(false); };
      document.getElementById('cfOk').onclick = () => { root.innerHTML = ''; resolve(true); };
    });
  },

  openModal(html) {
    const root = document.getElementById('modalRoot');
    root.innerHTML = `<div class="modal-overlay" id="modalOverlay"><div class="modal-box">${html}</div></div>`;
    document.getElementById('modalOverlay').addEventListener('click', e => {
      if (e.target.id === 'modalOverlay') UI.closeModal();
    });
  },

  closeModal() {
    document.getElementById('modalRoot').innerHTML = '';
  },

  validateField(fieldId, isValid) {
    const el = document.getElementById(fieldId);
    if (!el) return;
    el.classList.toggle('invalid', !isValid);
  }
};

/* ===================== Validaciones ===================== */
const Validate = {
  required(v) { return v !== undefined && v !== null && String(v).trim().length > 0; },
  email(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); },
  phone(v) { return /^[0-9+\-\s()]{7,15}$/.test(v); },
  positiveNumber(v) { return !isNaN(v) && Number(v) > 0; }
};

/* =====================================================================
   PÁGINA: LOGIN (index.html)
   ===================================================================== */
function initLoginPage() {
  guardHistoryNavigation('login');
  let captcha = Security.randomCaptcha();
  const questionEl = document.getElementById('captchaQuestion');
  questionEl.textContent = `¿Cuánto es ${captcha.a} + ${captcha.b}?`;

  const form = document.getElementById('loginForm');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const captchaAnswer = document.getElementById('captchaAnswer').value;

    let valid = true;
    UI.validateField('fUser', Validate.required(username)); if (!Validate.required(username)) valid = false;
    UI.validateField('fPass', Validate.required(password)); if (!Validate.required(password)) valid = false;

    const captchaOk = Number(captchaAnswer) === captcha.answer;
    UI.validateField('fCaptcha', captchaOk);
    if (!captchaOk) valid = false;

    if (!valid) return;

    const result = await Auth.login(username, password);
    if (!result.ok) {
      UI.toast(result.msg, 'error');
      captcha = Security.randomCaptcha();
      questionEl.textContent = `¿Cuánto es ${captcha.a} + ${captcha.b}?`;
      document.getElementById('captchaAnswer').value = '';
      return;
    }

    UI.toast('Bienvenido, ' + result.user.username, 'success');
    // replace() evita que "index.html" quede en el historial tras entrar
    setTimeout(() => window.location.replace('dashboard.html'), 400);
  });
}

/* =====================================================================
   PÁGINA: DASHBOARD (dashboard.html)
   ===================================================================== */
const NAV_CONFIG = {
  admin: [
    { key: 'dashboard', label: 'Panel', icon: '📊' },
    { key: 'mesas', label: 'Mesas', icon: '🍽️' },
    { key: 'reservas', label: 'Reservas', icon: '📅' },
    { key: 'pedidos', label: 'Pedidos y platos', icon: '🧾' },
    { key: 'cocina', label: 'Cocina', icon: '👨‍🍳' },
    { key: 'despachos', label: 'Despachos', icon: '🚚' },
    { key: 'usuarios', label: 'Usuarios', icon: '👥' }
  ],
  mesero: [
    { key: 'dashboard', label: 'Panel', icon: '📊' },
    { key: 'mesas', label: 'Mesas', icon: '🍽️' },
    { key: 'reservas', label: 'Reservas', icon: '📅' },
    { key: 'pedidos', label: 'Pedidos', icon: '🧾' }
  ],
  cocina: [
    { key: 'dashboard', label: 'Panel', icon: '📊' },
    { key: 'cocina', label: 'Cocina', icon: '👨‍🍳' }
  ],
  despacho: [
    { key: 'dashboard', label: 'Panel', icon: '📊' },
    { key: 'despachos', label: 'Despachos', icon: '🚚' }
  ]
};

const VIEW_TITLES = {
  dashboard: 'Panel de control', mesas: 'Gestión de mesas', reservas: 'Gestión de reservas',
  pedidos: 'Pedidos y platos', cocina: 'Cocina', despachos: 'Despachos', usuarios: 'Usuarios'
};

let currentUser = null;

function initDashboardPage() {
  guardHistoryNavigation('dashboard');
  currentUser = Auth.requireAuth();
  if (!currentUser) return;

  document.getElementById('sbUserName').textContent = currentUser.username;
  document.getElementById('sbUserRole').textContent = currentUser.role;
  document.getElementById('topDate').textContent = new Date().toLocaleDateString('es-CO', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  buildSidebar();

  document.getElementById('logoutBtn').addEventListener('click', () => Auth.logout());
  document.getElementById('burgerBtn').addEventListener('click', toggleSidebar);
  document.getElementById('sidebarOverlay').addEventListener('click', toggleSidebar);

  window.addEventListener('hashchange', route);
  route();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebarOverlay').classList.toggle('show');
}

function buildSidebar() {
  const nav = document.getElementById('sidebarNav');
  const items = NAV_CONFIG[currentUser.role] || [];
  nav.innerHTML = items.map(i =>
    `<div class="nav-item" data-key="${i.key}"><span class="icon">${i.icon}</span><span>${i.label}</span></div>`
  ).join('');
  nav.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', () => { window.location.hash = el.dataset.key; });
  });
}

function route() {
  // Re-verifica el usuario y su rol en cada cambio de vista (anti-manipulación)
  currentUser = Auth.requireAuth();
  if (!currentUser) return;

  const allowed = (NAV_CONFIG[currentUser.role] || []).map(i => i.key);
  let key = (window.location.hash || '#dashboard').slice(1);
  if (!allowed.includes(key)) key = 'dashboard';

  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.key === key));
  document.getElementById('viewTitle').textContent = VIEW_TITLES[key] || 'Panel';
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('show');

  const renderers = {
    dashboard: renderDashboardView, mesas: renderTablesView, reservas: renderReservationsView,
    pedidos: renderOrdersView, cocina: renderKitchenView, despachos: renderDispatchView, usuarios: renderUsersView
  };
  (renderers[key] || renderDashboardView)();
}

/* ===================== Lógica de estado de mesas por reserva ===================== */
function syncTableStatesWithReservations() {
  const now = new Date();
  DB.reservations.forEach(r => {
    const table = DB.tables.find(t => t.id === r.tableId);
    if (!table) return;
    const resDateTime = new Date(`${r.date}T${r.time}`);
    if (table.state !== 'occupied') {
      table.state = now >= resDateTime ? 'occupied' : 'reserved';
    }
  });
}

/* ===================== Vista: Dashboard ===================== */
function renderDashboardView() {
  syncTableStatesWithReservations();
  const view = document.getElementById('viewContent');
  const today = UI.today();

  const reservationsToday = DB.reservations.filter(r => r.date === today).length;
  const pendingDishes = DB.orders.flatMap(o => o.dishes).filter(d => d.status === 'pending').length;
  const preparingDishes = DB.orders.flatMap(o => o.dishes).filter(d => d.status === 'preparing').length;
  const activeDispatches = DB.dispatches.filter(d => d.status !== 'delivered').length;
  const deliveredToday = DB.dispatches.filter(d => d.status === 'delivered').length;
  const occupiedTables = DB.tables.filter(t => t.state === 'occupied').length;
  const activeOrders = DB.orders.filter(o => o.dishes.some(d => d.status !== 'delivered')).length;
  const revenueToday = DB.orders.reduce((sum, o) => sum + o.total, 0);

  let statCards = [];
  if (currentUser.role === 'admin') {
    statCards = [
      { val: reservationsToday, lbl: 'Reservas de hoy' },
      { val: pendingDishes, lbl: 'Platos pendientes' },
      { val: activeDispatches, lbl: 'Despachos activos' },
      { val: occupiedTables, lbl: 'Mesas ocupadas' },
      { val: DB.users.length, lbl: 'Usuarios totales' },
      { val: UI.money(revenueToday), lbl: 'Ingresos del día (est.)' }
    ];
  } else if (currentUser.role === 'mesero') {
    statCards = [
      { val: reservationsToday, lbl: 'Reservas de hoy' },
      { val: occupiedTables, lbl: 'Mesas ocupadas' },
      { val: activeOrders, lbl: 'Pedidos activos' }
    ];
  } else if (currentUser.role === 'cocina') {
    statCards = [
      { val: pendingDishes, lbl: 'Platos pendientes' },
      { val: preparingDishes, lbl: 'Platos en preparación' }
    ];
  } else if (currentUser.role === 'despacho') {
    statCards = [
      { val: activeDispatches, lbl: 'Despachos activos' },
      { val: deliveredToday, lbl: 'Entregas del día' }
    ];
  }

  const recentReservations = [...DB.reservations]
    .sort((a, b) => new Date(`${a.date}T${a.time}`) - new Date(`${b.date}T${b.time}`))
    .slice(0, 6);

  view.innerHTML = `
    <div class="stats-grid">
      ${statCards.map(s => `<div class="stat-card"><div class="val">${s.val}</div><div class="lbl">${s.lbl}</div></div>`).join('')}
    </div>

    <div class="section-card">
      <div class="section-head"><h2>Reservas activas</h2></div>
      ${recentReservations.length ? `
      <div class="table-wrap"><table>
        <thead><tr><th>Cliente</th><th>Mesa</th><th>Hora</th><th>Personas</th><th>Platos</th><th>Precio</th></tr></thead>
        <tbody>
          ${recentReservations.map(r => {
            const table = DB.tables.find(t => t.id === r.tableId);
            const order = DB.orders.find(o => o.tableId === r.tableId);
            const dishCount = order ? order.dishes.reduce((s, d) => s + d.quantity, 0) : 0;
            return `<tr>
              <td>${Security.sanitize(r.clientName)}</td>
              <td>${table ? Security.sanitize(table.name) : '-'}</td>
              <td>${Security.sanitize(r.time)}</td>
              <td>${r.people}</td>
              <td>${dishCount || '-'}</td>
              <td>${order ? UI.money(order.total) : '-'}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table></div>` : `<div class="empty-state"><div class="icon">📅</div>Sin reservas registradas</div>`}
    </div>

    <div class="section-card">
      <div class="section-head"><h2>Estado de mesas</h2></div>
      <div class="tables-grid">
        ${DB.tables.map(t => `
          <div class="table-tile ${t.state}" data-id="${t.id}">
            <span class="icon">🍽️</span>
            <span>${Security.sanitize(t.name)}</span>
            <small>${t.state === 'available' ? 'Disponible' : t.state === 'reserved' ? 'Reservada' : 'Ocupada'}</small>
          </div>`).join('')}
      </div>
    </div>
  `;

  view.querySelectorAll('.table-tile').forEach(el => {
    el.addEventListener('click', () => showTableInfoModal(el.dataset.id));
  });
}

function showTableInfoModal(tableId) {
  const table = DB.tables.find(t => t.id === tableId);
  if (!table) return;
  const reservation = DB.reservations.find(r => r.tableId === tableId);
  const stateLabel = { available: 'Disponible', reserved: 'Reservada', occupied: 'Ocupada' }[table.state];

  UI.openModal(`
    <div class="modal-head"><h3>${Security.sanitize(table.name)}</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <p><strong>Capacidad:</strong> ${table.capacity} personas</p>
    <p><strong>Zona:</strong> ${Security.sanitize(table.zone)}</p>
    <p><strong>Estado:</strong> <span class="badge badge-${table.state}">${stateLabel}</span></p>
    ${reservation ? `
      <hr style="margin:14px 0;border-color:var(--cream-dark)">
      <p><strong>Reserva:</strong> ${Security.sanitize(reservation.clientName)}</p>
      <p><strong>Hora:</strong> ${Security.sanitize(reservation.date)} ${Security.sanitize(reservation.time)}</p>
      <p><strong>Personas:</strong> ${reservation.people}</p>
    ` : ''}
    <div class="modal-actions"><button class="btn btn-ghost" onclick="UI.closeModal()">Cerrar</button></div>
  `);
}

/* ===================== Vista: Mesas ===================== */
function renderTablesView() {
  const view = document.getElementById('viewContent');
  const isAdmin = currentUser.role === 'admin';

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head">
        <h2>Mesas registradas</h2>
        ${isAdmin ? `<button class="btn btn-gold" id="addTableBtn">+ Nueva mesa</button>` : ''}
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Nombre</th><th>Capacidad</th><th>Zona</th><th>Estado</th>${isAdmin ? '<th>Acciones</th>' : ''}</tr></thead>
        <tbody>
          ${DB.tables.map(t => `
            <tr>
              <td>${t.id}</td>
              <td>${Security.sanitize(t.name)}</td>
              <td>${t.capacity}</td>
              <td>${Security.sanitize(t.zone)}</td>
              <td><span class="badge badge-${t.state}">${t.state === 'available' ? 'Disponible' : t.state === 'reserved' ? 'Reservada' : 'Ocupada'}</span></td>
              ${isAdmin ? `<td class="row-actions">
                <button class="btn btn-sm btn-ghost" data-action="quick" data-id="${t.id}">Cambiar</button>
                <button class="btn btn-sm btn-ghost" data-action="edit" data-id="${t.id}">Editar</button>
                <button class="btn btn-sm btn-danger" data-action="delete" data-id="${t.id}">Eliminar</button>
              </td>` : ''}
            </tr>`).join('')}
        </tbody>
      </table></div>
    </div>
  `;

  if (isAdmin) {
    document.getElementById('addTableBtn').addEventListener('click', () => openTableForm());
    view.querySelectorAll('[data-action="edit"]').forEach(b => b.addEventListener('click', () => openTableForm(b.dataset.id)));
    view.querySelectorAll('[data-action="delete"]').forEach(b => b.addEventListener('click', () => deleteTable(b.dataset.id)));
    view.querySelectorAll('[data-action="quick"]').forEach(b => b.addEventListener('click', () => quickToggleTable(b.dataset.id)));
  }
}

function quickToggleTable(id) {
  const table = DB.tables.find(t => t.id === id);
  if (!table) return;
  const hasActiveReservation = DB.reservations.some(r => r.tableId === id);
  if (hasActiveReservation) {
    UI.toast('No se puede cambiar: la mesa tiene una reserva activa.', 'error');
    return;
  }
  table.state = table.state === 'occupied' ? 'available' : 'occupied';
  Store.save(DB);
  renderTablesView();
  UI.toast('Estado de mesa actualizado.', 'success');
}

function openTableForm(id) {
  const editing = !!id;
  const table = editing ? DB.tables.find(t => t.id === id) : null;
  const nextNumber = DB.tables.length + 1;

  UI.openModal(`
    <div class="modal-head"><h3>${editing ? 'Editar mesa' : 'Nueva mesa'}</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="tableForm">
      <div class="field"><label>Nombre</label>
        <input id="tName" value="${editing ? Security.sanitize(table.name) : 'Mesa ' + nextNumber}" ${editing ? '' : 'readonly'}>
      </div>
      <div class="field"><label>Capacidad</label><input type="number" id="tCapacity" min="1" value="${editing ? table.capacity : 4}"></div>
      <div class="field"><label>Zona</label>
        <select id="tZone">
          ${['Interior', 'Terraza', 'Barra'].map(z => `<option ${editing && table.zone === z ? 'selected' : ''}>${z}</option>`).join('')}
        </select>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Guardar</button>
      </div>
    </form>
  `);

  document.getElementById('tableForm').addEventListener('submit', e => {
    e.preventDefault();
    const capacity = document.getElementById('tCapacity').value;
    const zone = document.getElementById('tZone').value;
    if (!Validate.positiveNumber(capacity)) { UI.toast('Capacidad inválida.', 'error'); return; }

    if (editing) {
      table.capacity = Number(capacity);
      table.zone = zone;
    } else {
      DB.tables.push({ id: Store.genId(DB.tables), name: 'Mesa ' + nextNumber, capacity: Number(capacity), zone, state: 'available' });
    }
    Store.save(DB);
    UI.closeModal();
    renderTablesView();
    UI.toast(editing ? 'Mesa actualizada.' : 'Mesa creada.', 'success');
  });
}

async function deleteTable(id) {
  const ok = await UI.confirmModal('Eliminar mesa', '¿Seguro que deseas eliminar esta mesa? Esta acción no se puede deshacer.');
  if (!ok) return;
  DB.tables = DB.tables.filter(t => t.id !== id);
  Store.save(DB);
  renderTablesView();
  UI.toast('Mesa eliminada.', 'success');
}

/* ===================== Vista: Reservas ===================== */
function renderReservationsView() {
  syncTableStatesWithReservations();
  const view = document.getElementById('viewContent');

  const sorted = [...DB.reservations].sort((a, b) => new Date(`${a.date}T${a.time}`) - new Date(`${b.date}T${b.time}`));

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head">
        <h2>Reservas</h2>
        <button class="btn btn-gold" id="addResBtn">+ Nueva reserva</button>
      </div>
      ${sorted.length ? `<div class="cards-grid">
        ${sorted.map(r => {
          const table = DB.tables.find(t => t.id === r.tableId);
          return `<div class="item-card">
            <h4>${Security.sanitize(r.clientName)}</h4>
            <div class="meta">
              <span>📞 ${Security.sanitize(r.phone)}</span>
              <span>✉️ ${Security.sanitize(r.email || '-')}</span>
              <span>🍽️ ${table ? Security.sanitize(table.name) : '-'} · 👥 ${r.people}</span>
              <span>📅 ${Security.sanitize(r.date)} ⏰ ${Security.sanitize(r.time)}</span>
              ${r.description ? `<span>📝 ${Security.sanitize(r.description)}</span>` : ''}
            </div>
            <div class="foot">
              <button class="btn btn-sm btn-ghost" data-action="edit" data-id="${r.id}">Editar</button>
              <button class="btn btn-sm btn-danger" data-action="delete" data-id="${r.id}">Eliminar</button>
            </div>
          </div>`;
        }).join('')}
      </div>` : `<div class="empty-state"><div class="icon">📅</div>Aún no hay reservas</div>`}
    </div>
  `;

  document.getElementById('addResBtn').addEventListener('click', () => openReservationForm());
  view.querySelectorAll('[data-action="edit"]').forEach(b => b.addEventListener('click', () => openReservationForm(b.dataset.id)));
  view.querySelectorAll('[data-action="delete"]').forEach(b => b.addEventListener('click', () => deleteReservation(b.dataset.id)));
}

function openReservationForm(id) {
  const editing = !!id;
  const res = editing ? DB.reservations.find(r => r.id === id) : null;
  const availableTables = DB.tables.filter(t => t.state === 'available' || (editing && t.id === res.tableId));

  UI.openModal(`
    <div class="modal-head"><h3>${editing ? 'Editar reserva' : 'Nueva reserva'}</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="resForm">
      <div class="field" id="fClient"><label>Cliente</label><input id="rClient" value="${editing ? Security.sanitize(res.clientName) : ''}"><div class="field-error">Nombre requerido.</div></div>
      <div class="field" id="fPhone"><label>Teléfono</label><input id="rPhone" value="${editing ? Security.sanitize(res.phone) : ''}"><div class="field-error">Teléfono inválido.</div></div>
      <div class="field"><label>Correo</label><input id="rEmail" value="${editing ? Security.sanitize(res.email) : ''}"></div>
      <div class="field" id="fTable"><label>Mesa</label>
        <select id="rTable">${availableTables.map(t => `<option value="${t.id}" ${editing && res.tableId === t.id ? 'selected' : ''}>${t.name} (cap. ${t.capacity})</option>`).join('')}</select>
        <div class="field-error">Selecciona una mesa disponible.</div>
      </div>
      <div class="field" id="fDate"><label>Fecha</label><input type="date" id="rDate" value="${editing ? res.date : UI.today()}"><div class="field-error">Fecha requerida.</div></div>
      <div class="field" id="fTime"><label>Hora</label><input type="time" id="rTime" value="${editing ? res.time : ''}"><div class="field-error">Hora requerida.</div></div>
      <div class="field" id="fPeople"><label>Personas</label><input type="number" id="rPeople" min="1" value="${editing ? res.people : 2}"><div class="field-error">Cantidad inválida.</div></div>
      <div class="field"><label>Descripción</label><textarea id="rDesc" rows="2">${editing ? Security.sanitize(res.description || '') : ''}</textarea></div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Guardar</button>
      </div>
    </form>
  `);

  document.getElementById('resForm').addEventListener('submit', e => {
    e.preventDefault();
    const clientName = document.getElementById('rClient').value.trim();
    const phone = document.getElementById('rPhone').value.trim();
    const email = document.getElementById('rEmail').value.trim();
    const tableId = document.getElementById('rTable').value;
    const date = document.getElementById('rDate').value;
    const time = document.getElementById('rTime').value;
    const people = document.getElementById('rPeople').value;
    const description = document.getElementById('rDesc').value.trim();

    let valid = true;
    UI.validateField('fClient', Validate.required(clientName)); if (!Validate.required(clientName)) valid = false;
    UI.validateField('fPhone', Validate.phone(phone)); if (!Validate.phone(phone)) valid = false;
    UI.validateField('fTable', Validate.required(tableId)); if (!Validate.required(tableId)) valid = false;
    UI.validateField('fDate', Validate.required(date)); if (!Validate.required(date)) valid = false;
    UI.validateField('fTime', Validate.required(time)); if (!Validate.required(time)) valid = false;
    UI.validateField('fPeople', Validate.positiveNumber(people)); if (!Validate.positiveNumber(people)) valid = false;
    if (email && !Validate.email(email)) { UI.toast('Correo inválido.', 'error'); valid = false; }
    if (!valid) return;

    if (editing) {
      Object.assign(res, { clientName, phone, email, tableId, date, time, people: Number(people), description });
    } else {
      DB.reservations.push({ id: Store.genId(DB.reservations), clientName, phone, email, tableId, date, time, people: Number(people), description });
    }

    const table = DB.tables.find(t => t.id === tableId);
    if (table && table.state === 'available') table.state = 'reserved';

    Store.save(DB);
    UI.closeModal();
    renderReservationsView();
    UI.toast(editing ? 'Reserva actualizada.' : 'Reserva creada.', 'success');
  });
}

async function deleteReservation(id) {
  const ok = await UI.confirmModal('Eliminar reserva', '¿Deseas eliminar esta reserva?');
  if (!ok) return;
  const res = DB.reservations.find(r => r.id === id);
  DB.reservations = DB.reservations.filter(r => r.id !== id);
  if (res) {
    const table = DB.tables.find(t => t.id === res.tableId);
    if (table && table.state !== 'occupied') table.state = 'available';
  }
  Store.save(DB);
  renderReservationsView();
  UI.toast('Reserva eliminada.', 'success');
}

/* ===================== Vista: Pedidos y platos ===================== */
function renderOrdersView() {
  const view = document.getElementById('viewContent');
  const isAdmin = currentUser.role === 'admin';

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head">
        <h2>Pedidos</h2>
        <button class="btn btn-gold" id="addOrderBtn">+ Nuevo pedido</button>
      </div>
      ${DB.orders.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Mesa</th><th>Platos</th><th>Total</th><th>Estado</th></tr></thead>
        <tbody>
          ${DB.orders.map(o => {
            const table = DB.tables.find(t => t.id === o.tableId);
            const allReady = o.dishes.every(d => d.status !== 'pending' && d.status !== 'preparing');
            return `<tr>
              <td>${table ? Security.sanitize(table.name) : '-'}</td>
              <td>${o.dishes.map(d => {
                const dish = DB.dishes.find(x => x.id === d.dishId);
                return `${dish ? Security.sanitize(dish.name) : '?'} x${d.quantity}`;
              }).join(', ')}</td>
              <td>${UI.money(o.total)}</td>
              <td>${o.dishes.map(d => `<span class="badge badge-${d.status}">${d.status === 'pending' ? 'Pendiente' : d.status === 'preparing' ? 'Preparando' : 'Listo'}</span>`).join(' ')}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table></div>` : `<div class="empty-state"><div class="icon">🧾</div>No hay pedidos registrados</div>`}
    </div>

    ${isAdmin ? `
    <div class="section-card">
      <div class="section-head"><h2>Platos del menú</h2><button class="btn btn-gold" id="addDishBtn">+ Nuevo plato</button></div>
      <div class="cards-grid">
        ${DB.dishes.map(d => `
          <div class="item-card">
            <div class="dish-emoji">${d.emoji || '☕'}</div>
            <h4>${Security.sanitize(d.name)}</h4>
            <div class="meta">${Security.sanitize(d.description)}</div>
            <div class="foot">
              <span class="dish-price">${UI.money(d.price)}</span>
              <div class="row-actions">
                <button class="btn btn-sm btn-ghost" data-action="editDish" data-id="${d.id}">Editar</button>
                <button class="btn btn-sm btn-danger" data-action="deleteDish" data-id="${d.id}">Eliminar</button>
              </div>
            </div>
          </div>`).join('')}
      </div>
    </div>` : ''}
  `;

  document.getElementById('addOrderBtn').addEventListener('click', () => openOrderForm());
  if (isAdmin) {
    document.getElementById('addDishBtn').addEventListener('click', () => openDishForm());
    view.querySelectorAll('[data-action="editDish"]').forEach(b => b.addEventListener('click', () => openDishForm(b.dataset.id)));
    view.querySelectorAll('[data-action="deleteDish"]').forEach(b => b.addEventListener('click', () => deleteDish(b.dataset.id)));
  }
}

function openOrderForm() {
  UI.openModal(`
    <div class="modal-head"><h3>Nuevo pedido</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="orderForm">
      <div class="field" id="fOrderTable"><label>Mesa</label>
        <select id="oTable">${DB.tables.map(t => `<option value="${t.id}">${Security.sanitize(t.name)}</option>`).join('')}</select>
      </div>
      <label style="display:block;font-size:.82rem;font-weight:700;color:var(--coffee-dark);margin:14px 0 6px">Platos</label>
      <div id="dishPickerList">
        ${DB.dishes.map(d => `
          <div class="dish-picker-row">
            <span class="name">${Security.sanitize(d.name)} · ${UI.money(d.price)}</span>
            <input type="number" min="0" value="0" class="qty-input" data-dish="${d.id}">
          </div>`).join('')}
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Crear pedido</button>
      </div>
    </form>
  `);

  document.getElementById('orderForm').addEventListener('submit', e => {
    e.preventDefault();
    const tableId = document.getElementById('oTable').value;
    const rows = document.querySelectorAll('#dishPickerList .qty-input');
    const dishes = [];
    let total = 0;

    rows.forEach(input => {
      const qty = Number(input.value);
      if (qty > 0) {
        const dish = DB.dishes.find(d => d.id === input.dataset.dish);
        dishes.push({ dishId: dish.id, quantity: qty, status: 'pending' });
        total += dish.price * qty;
      }
    });

    if (!dishes.length) { UI.toast('Selecciona al menos un plato.', 'error'); return; }

    DB.orders.push({ id: Store.genId(DB.orders), tableId, dishes, total, createdAt: new Date().toISOString() });
    const table = DB.tables.find(t => t.id === tableId);
    if (table && table.state === 'available') table.state = 'occupied';

    Store.save(DB);
    UI.closeModal();
    renderOrdersView();
    UI.toast('Pedido creado.', 'success');
  });
}

function openDishForm(id) {
  const editing = !!id;
  const dish = editing ? DB.dishes.find(d => d.id === id) : null;

  UI.openModal(`
    <div class="modal-head"><h3>${editing ? 'Editar plato' : 'Nuevo plato'}</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="dishForm">
      <div class="field" id="fDishName"><label>Nombre</label><input id="dName" value="${editing ? Security.sanitize(dish.name) : ''}"><div class="field-error">Nombre requerido.</div></div>
      <div class="field"><label>Descripción</label><textarea id="dDesc" rows="2">${editing ? Security.sanitize(dish.description) : ''}</textarea></div>
      <div class="field" id="fDishPrice"><label>Precio</label><input type="number" id="dPrice" min="0" value="${editing ? dish.price : ''}"><div class="field-error">Precio inválido.</div></div>
      <div class="field"><label>Ícono</label>
        <select id="dEmoji">${DISH_EMOJIS.map(e => `<option ${editing && dish.emoji === e ? 'selected' : ''}>${e}</option>`).join('')}</select>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Guardar</button>
      </div>
    </form>
  `);

  document.getElementById('dishForm').addEventListener('submit', e => {
    e.preventDefault();
    const name = document.getElementById('dName').value.trim();
    const description = document.getElementById('dDesc').value.trim();
    const price = document.getElementById('dPrice').value;
    const emoji = document.getElementById('dEmoji').value;

    let valid = true;
    UI.validateField('fDishName', Validate.required(name)); if (!Validate.required(name)) valid = false;
    UI.validateField('fDishPrice', Validate.positiveNumber(price)); if (!Validate.positiveNumber(price)) valid = false;
    if (!valid) return;

    if (editing) {
      Object.assign(dish, { name, description, price: Number(price), emoji });
    } else {
      DB.dishes.push({ id: Store.genId(DB.dishes), name, description, price: Number(price), emoji });
    }
    Store.save(DB);
    UI.closeModal();
    renderOrdersView();
    UI.toast(editing ? 'Plato actualizado.' : 'Plato creado.', 'success');
  });
}

async function deleteDish(id) {
  const ok = await UI.confirmModal('Eliminar plato', '¿Deseas eliminar este plato del menú?');
  if (!ok) return;
  DB.dishes = DB.dishes.filter(d => d.id !== id);
  Store.save(DB);
  renderOrdersView();
  UI.toast('Plato eliminado.', 'success');
}

/* ===================== Vista: Cocina ===================== */
function renderKitchenView() {
  const view = document.getElementById('viewContent');
  const pendingItems = [];

  DB.orders.forEach(order => {
    order.dishes.forEach((d, idx) => {
      if (d.status === 'pending' || d.status === 'preparing') {
        const dish = DB.dishes.find(x => x.id === d.dishId);
        const table = DB.tables.find(t => t.id === order.tableId);
        pendingItems.push({ orderId: order.id, dishIndex: idx, dishName: dish ? dish.name : '?', tableName: table ? table.name : '?', status: d.status, quantity: d.quantity });
      }
    });
  });

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head"><h2>Platos por preparar</h2></div>
      ${pendingItems.length ? pendingItems.map(item => `
        <div class="kanban-item">
          <div class="info">
            <strong>${Security.sanitize(item.dishName)} x${item.quantity}</strong>
            <span>${Security.sanitize(item.tableName)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="badge badge-${item.status}">${item.status === 'pending' ? 'Pendiente' : 'Preparando'}</span>
            ${item.status === 'pending' ? `<button class="btn btn-sm btn-gold" data-action="prep" data-order="${item.orderId}" data-idx="${item.dishIndex}">Preparar</button>` : ''}
            ${item.status === 'preparing' ? `<button class="btn btn-sm btn-gold" data-action="ready" data-order="${item.orderId}" data-idx="${item.dishIndex}">Marcar listo</button>` : ''}
          </div>
        </div>
      `).join('') : `<div class="empty-state"><div class="icon">👨‍🍳</div>No hay platos pendientes</div>`}
    </div>
  `;

  view.querySelectorAll('[data-action="prep"]').forEach(b => b.addEventListener('click', () => updateDishStatus(b.dataset.order, b.dataset.idx, 'preparing')));
  view.querySelectorAll('[data-action="ready"]').forEach(b => b.addEventListener('click', () => updateDishStatus(b.dataset.order, b.dataset.idx, 'ready')));
}

function updateDishStatus(orderId, idx, status) {
  const order = DB.orders.find(o => o.id === orderId);
  if (!order) return;
  order.dishes[idx].status = status;
  Store.save(DB);
  renderKitchenView();
  UI.toast('Estado del plato actualizado.', 'success');
}

/* ===================== Vista: Despachos ===================== */
function renderDispatchView() {
  const view = document.getElementById('viewContent');

  // Platos listos que aún no están en ningún despacho
  const dispatchedDishKeys = new Set();
  DB.dispatches.forEach(d => d.dishesIds.forEach(k => dispatchedDishKeys.add(k)));

  const readyToDispatch = [];
  DB.orders.forEach(order => {
    order.dishes.forEach((d, idx) => {
      const key = `${order.id}-${idx}`;
      if (d.status === 'ready' && !dispatchedDishKeys.has(key)) {
        const dish = DB.dishes.find(x => x.id === d.dishId);
        const table = DB.tables.find(t => t.id === order.tableId);
        readyToDispatch.push({ key, dishName: dish ? dish.name : '?', tableName: table ? table.name : '?', quantity: d.quantity });
      }
    });
  });

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head">
        <h2>Platos listos para despachar</h2>
        ${readyToDispatch.length ? `<button class="btn btn-gold" id="createDispatchBtn">+ Crear despacho</button>` : ''}
      </div>
      ${readyToDispatch.length ? readyToDispatch.map(item => `
        <div class="kanban-item">
          <div class="info"><strong>${Security.sanitize(item.dishName)} x${item.quantity}</strong><span>${Security.sanitize(item.tableName)}</span></div>
          <span class="badge badge-listo">Listo</span>
        </div>`).join('') : `<div class="empty-state"><div class="icon">✅</div>No hay platos listos por despachar</div>`}
    </div>

    <div class="section-card">
      <div class="section-head"><h2>Despachos</h2></div>
      ${DB.dispatches.length ? DB.dispatches.map(d => {
        const order = DB.orders.find(o => o.id === d.orderId);
        const table = order ? DB.tables.find(t => t.id === order.tableId) : null;
        const statusLabel = { pending: 'Preparado', en_route: 'En ruta', delivered: 'Entregado' }[d.status];
        return `<div class="kanban-item">
          <div class="info"><strong>Despacho #${d.id}</strong><span>${table ? Security.sanitize(table.name) : '-'} · ${d.dishesIds.length} ítem(s)</span></div>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="badge badge-${d.status}">${statusLabel}</span>
            ${d.status === 'pending' ? `<button class="btn btn-sm btn-gold" data-action="route" data-id="${d.id}">Enviar</button>` : ''}
            ${d.status === 'en_route' ? `<button class="btn btn-sm btn-gold" data-action="deliver" data-id="${d.id}">Entregado</button>` : ''}
          </div>
        </div>`;
      }).join('') : `<div class="empty-state"><div class="icon">🚚</div>No hay despachos registrados</div>`}
    </div>
  `;

  const createBtn = document.getElementById('createDispatchBtn');
  if (createBtn) createBtn.addEventListener('click', () => openDispatchForm(readyToDispatch));
  view.querySelectorAll('[data-action="route"]').forEach(b => b.addEventListener('click', () => updateDispatchStatus(b.dataset.id, 'en_route')));
  view.querySelectorAll('[data-action="deliver"]').forEach(b => b.addEventListener('click', () => updateDispatchStatus(b.dataset.id, 'delivered')));
}

function openDispatchForm(readyToDispatch) {
  UI.openModal(`
    <div class="modal-head"><h3>Crear despacho</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="dispatchForm">
      ${readyToDispatch.map(item => `
        <div class="dish-picker-row">
          <span class="name">${Security.sanitize(item.dishName)} x${item.quantity} · ${Security.sanitize(item.tableName)}</span>
          <input type="checkbox" data-key="${item.key}">
        </div>`).join('')}
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Crear</button>
      </div>
    </form>
  `);

  document.getElementById('dispatchForm').addEventListener('submit', e => {
    e.preventDefault();
    const checked = Array.from(document.querySelectorAll('#dispatchForm input[type=checkbox]:checked')).map(c => c.dataset.key);
    if (!checked.length) { UI.toast('Selecciona al menos un plato.', 'error'); return; }

    const orderId = checked[0].split('-')[0];
    DB.dispatches.push({ id: Store.genId(DB.dispatches), orderId, dishesIds: checked, status: 'pending' });
    Store.save(DB);
    UI.closeModal();
    renderDispatchView();
    UI.toast('Despacho creado.', 'success');
  });
}

function updateDispatchStatus(id, status) {
  const dispatch = DB.dispatches.find(d => d.id === id);
  if (!dispatch) return;
  dispatch.status = status;
  Store.save(DB);
  renderDispatchView();
  UI.toast('Estado del despacho actualizado.', 'success');
}

/* ===================== Vista: Usuarios ===================== */
function renderUsersView() {
  const view = document.getElementById('viewContent');

  view.innerHTML = `
    <div class="section-card">
      <div class="section-head">
        <h2>Usuarios</h2>
        <button class="btn btn-gold" id="addUserBtn">+ Nuevo usuario</button>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Usuario</th><th>Rol</th><th>Acciones</th></tr></thead>
        <tbody>
          ${DB.users.map(u => `
            <tr>
              <td>${Security.sanitize(u.username)}</td>
              <td style="text-transform:capitalize">${Security.sanitize(u.role)}</td>
              <td class="row-actions">
                <button class="btn btn-sm btn-ghost" data-action="edit" data-id="${u.id}">Editar</button>
                <button class="btn btn-sm btn-danger" data-action="delete" data-id="${u.id}">Eliminar</button>
              </td>
            </tr>`).join('')}
        </tbody>
      </table></div>
    </div>

    <div class="section-card">
      <div class="section-head"><h2>Datos de demostración</h2></div>
      <p class="text-muted">Restablece toda la información a los valores iniciales (usuarios, mesas y platos).</p>
      <button class="btn btn-danger" id="resetDemoBtn" style="margin-top:12px">Restablecer datos demo</button>
    </div>
  `;

  document.getElementById('addUserBtn').addEventListener('click', () => openUserForm());
  view.querySelectorAll('[data-action="edit"]').forEach(b => b.addEventListener('click', () => openUserForm(b.dataset.id)));
  view.querySelectorAll('[data-action="delete"]').forEach(b => b.addEventListener('click', () => deleteUser(b.dataset.id)));
  document.getElementById('resetDemoBtn').addEventListener('click', resetDemoData);
}

function openUserForm(id) {
  const editing = !!id;
  const user = editing ? DB.users.find(u => u.id === id) : null;

  UI.openModal(`
    <div class="modal-head"><h3>${editing ? 'Editar usuario' : 'Nuevo usuario'}</h3><button class="modal-close" onclick="UI.closeModal()">✕</button></div>
    <form id="userForm">
      <div class="field" id="fUName"><label>Nombre de usuario</label><input id="uName" value="${editing ? Security.sanitize(user.username) : ''}" ${editing ? 'readonly' : ''}><div class="field-error">Nombre requerido.</div></div>
      <div class="field"><label>Rol</label>
        <select id="uRole" ${editing ? 'disabled' : ''}>${ROLES.map(r => `<option ${editing && user.role === r ? 'selected' : ''}>${r}</option>`).join('')}</select>
      </div>
      <hr style="margin:16px 0;border-color:var(--cream-dark)">
      ${editing ? `
        <p class="text-muted" style="margin-bottom:10px">Para cambiar la contraseña, confirma tu contraseña de administrador.</p>
        <div class="field" id="fAdminPass"><label>Tu contraseña (admin)</label><input type="password" id="uAdminPass"><div class="field-error">Contraseña incorrecta.</div></div>
      ` : ''}
      <div class="field" id="fNewPass"><label>${editing ? 'Nueva contraseña' : 'Contraseña'}</label><input type="password" id="uPass"><div class="field-error">Mínimo 6 caracteres.</div></div>
      <div class="field" id="fRepPass"><label>Repetir contraseña</label><input type="password" id="uPassRep"><div class="field-error">Las contraseñas no coinciden.</div></div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" onclick="UI.closeModal()">Cancelar</button>
        <button type="submit" class="btn btn-gold">Guardar</button>
      </div>
    </form>
  `);

  document.getElementById('userForm').addEventListener('submit', async e => {
    e.preventDefault();
    const username = document.getElementById('uName').value.trim();
    const role = document.getElementById('uRole').value;
    const pass = document.getElementById('uPass').value;
    const passRep = document.getElementById('uPassRep').value;

    let valid = true;

    if (editing) {
      const adminPass = document.getElementById('uAdminPass').value;
      const adminOk = await Security.verifyPassword(adminPass, currentUser.passwordHash);
      UI.validateField('fAdminPass', adminOk);
      if (!adminOk) valid = false;
    } else {
      UI.validateField('fUName', Validate.required(username) && !DB.users.some(u => u.username === username));
      if (!Validate.required(username) || DB.users.some(u => u.username === username)) valid = false;
    }

    const passOk = pass.length >= 6;
    UI.validateField('fNewPass', passOk); if (!passOk) valid = false;
    const repOk = pass === passRep;
    UI.validateField('fRepPass', repOk); if (!repOk) valid = false;

    if (!valid) return;

    const newHash = await Security.hashPassword(pass);

    if (editing) {
      user.passwordHash = newHash;
    } else {
      DB.users.push({ id: Store.genId(DB.users), username, passwordHash: newHash, role });
    }

    Store.save(DB);
    UI.closeModal();
    renderUsersView();
    UI.toast(editing ? 'Usuario actualizado.' : 'Usuario creado.', 'success');
  });
}

async function deleteUser(id) {
  if (id === currentUser.id) { UI.toast('No puedes eliminar tu propio usuario.', 'error'); return; }
  const ok = await UI.confirmModal('Eliminar usuario', '¿Deseas eliminar este usuario?');
  if (!ok) return;
  DB.users = DB.users.filter(u => u.id !== id);
  Store.save(DB);
  renderUsersView();
  UI.toast('Usuario eliminado.', 'success');
}

async function resetDemoData() {
  const ok = await UI.confirmModal('Restablecer datos', 'Se eliminarán todos los datos actuales y se restaurarán los valores iniciales. ¿Continuar?');
  if (!ok) return;
  DB = await Store.reset();
  Auth.logout();
}

/* ===================== Arranque ===================== */
document.addEventListener('DOMContentLoaded', async () => {
  DB = await Store.init();

  if (document.getElementById('loginForm')) {
    initLoginPage();
  } else if (document.getElementById('viewContent')) {
    initDashboardPage();
  }
});
