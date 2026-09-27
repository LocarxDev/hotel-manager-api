// Hotel Manager PRO — API multi-hotel
// Node + Express + Postgres. Cada hotel só enxerga os próprios dados (hotel_id).
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, migrate } = require('./db');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('ERRO: defina JWT_SECRET (mínimo 16 caracteres).');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const origins = (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: origins.includes('*') ? true : origins }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cache-Control', 'no-store');
  next();
});

/* ============================== utilidades ============================== */
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

class Erro extends Error {
  constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra; }
}
const falha = (status, msg, extra) => { throw new Erro(status, msg, extra); };

const num = (v, def = 0) => { const n = Number(v); return Number.isFinite(n) ? n : def; };
const txt = v => (v === undefined || v === null) ? null : String(v).trim() || null;
const soDigitos = v => String(v || '').replace(/\D/g, '');
const dataValida = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')) && !isNaN(Date.parse(d + 'T00:00:00Z'));

function cpfValido(cpf) {
  cpf = soDigitos(cpf);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  for (let t = 9; t < 11; t++) {
    let s = 0;
    for (let i = 0; i < t; i++) s += Number(cpf[i]) * (t + 1 - i);
    const d = ((10 * s) % 11) % 10;
    if (d !== Number(cpf[t])) return false;
  }
  return true;
}

function hojeTz(tz) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}
function horaTz(tz) {
  return new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date());
}
function somaDias(d, n) {
  const dt = new Date(d + 'T12:00:00Z');
  dt.setUTCDate(dt.getUTCDate() + n);
  return dt.toISOString().slice(0, 10);
}
function diffDias(a, b) {
  return Math.round((Date.parse(b + 'T12:00:00Z') - Date.parse(a + 'T12:00:00Z')) / 86400000);
}
const minutos = hhmm => { const [h, m] = String(hhmm || '0:0').split(':').map(Number); return h * 60 + (m || 0); };

const CONFIG_PADRAO = {
  checkinHora: '14:00',
  checkoutHora: '12:00',
  toleranciaMin: 30,
  taxaCheckoutTardio: 0,
  permitirCheckinAntecipado: true,
  bloquearCheckoutComSaldo: false,
  fuso: 'America/Sao_Paulo',
  tiposQuarto: ['Solteiro', 'Casal', 'Duplo', 'Triplo', 'Quádruplo', 'Suíte', 'Suíte Master'],
  formasPagamento: ['PIX', 'Dinheiro', 'Cartão de Crédito', 'Cartão de Débito', 'Transferência', 'Faturado'],
  origens: ['Balcão', 'Telefone', 'WhatsApp', 'Site', 'Booking.com', 'Airbnb', 'Expedia', 'Agência', 'Empresa'],
  textoRecibo: 'Obrigado pela preferência. Volte sempre!'
};

async function getCfg(hotelId, db = pool) {
  const { rows } = await db.query('SELECT dados FROM configuracoes WHERE hotel_id=$1', [hotelId]);
  return { ...CONFIG_PADRAO, ...(rows[0]?.dados || {}) };
}

/* ============================== permissões ============================== */
const TODAS = [
  'reservas.ver', 'reservas.editar', 'reservas.excluir',
  'hospedes.ver', 'hospedes.editar', 'hospedes.excluir',
  'pagamentos.registrar', 'pagamentos.estornar', 'consumos.editar',
  'financeiro.ver', 'relatorios.ver',
  'quartos.cadastro', 'quartos.status', 'governanca',
  'config.editar', 'usuarios', 'auditoria'
];
const PERMISSOES = {
  admin: TODAS,
  gerente: TODAS.filter(p => p !== 'usuarios'),
  recepcao: ['reservas.ver', 'reservas.editar', 'hospedes.ver', 'hospedes.editar',
    'pagamentos.registrar', 'consumos.editar', 'financeiro.ver', 'quartos.status', 'governanca'],
  camareira: ['governanca', 'quartos.status']
};
const PAPEIS_HOTEL = Object.keys(PERMISSOES);

async function audit(req, acao, detalhe, hotelId) {
  try {
    await pool.query(
      'INSERT INTO auditoria (hotel_id, usuario_id, usuario_nome, acao, detalhe) VALUES ($1,$2,$3,$4,$5)',
      [hotelId ?? req.user.hotel_id, req.user.id, req.user.nome, acao, detalhe || null]
    );
  } catch (e) { console.error('auditoria', e.message); }
}

/* ============================== autenticação ============================== */
const tentativas = new Map();
function limiteLogin(chave) {
  const agora = Date.now();
  const t = (tentativas.get(chave) || []).filter(x => agora - x < 15 * 60 * 1000);
  tentativas.set(chave, t);
  return t.length >= 8;
}

async function carregarUsuario(uid) {
  const { rows } = await pool.query(
    `SELECT u.id, u.hotel_id, u.nome, u.login, u.papel, u.ativo,
            h.nome AS hotel_nome, h.status AS hotel_status, h.motivo_bloqueio
       FROM usuarios u LEFT JOIN hoteis h ON h.id = u.hotel_id WHERE u.id=$1`, [uid]);
  return rows[0];
}

function mensagemBloqueio(u) {
  return 'O acesso deste hotel está suspenso' + (u.motivo_bloqueio ? ` (${u.motivo_bloqueio})` : '') +
    '. Entre em contato com o suporte para regularizar.';
}

const auth = wrap(async (req, res, next) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) falha(401, 'Faça login para continuar.');
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { falha(401, 'Sessão expirada. Faça login novamente.'); }
  const u = await carregarUsuario(payload.uid);
  if (!u || !u.ativo) falha(401, 'Usuário desativado.');
  if (u.papel !== 'master' && u.hotel_status !== 'ativo') falha(403, mensagemBloqueio(u), { bloqueado: true });
  req.user = u;
  next();
});

const soMaster = (req, res, next) => (req.user.papel === 'master' ? next() : next(new Erro(403, 'Acesso restrito ao painel Master.')));
const doHotel = (req, res, next) => (req.user.hotel_id ? next() : next(new Erro(403, 'Esta área é dos hotéis. Use o painel Master.')));
const pode = perm => (req, res, next) =>
  (PERMISSOES[req.user.papel] || []).includes(perm) ? next() : next(new Erro(403, 'Seu perfil não tem permissão para esta ação.'));

function perfilPublico(u, cfg) {
  return {
    id: u.id, nome: u.nome, login: u.login, papel: u.papel,
    hotel: u.hotel_id ? { id: u.hotel_id, nome: u.hotel_nome } : null,
    permissoes: u.papel === 'master' ? [] : PERMISSOES[u.papel] || [],
    config: cfg || null
  };
}

app.get('/', (req, res) => res.json({ ok: true, app: 'Hotel Manager PRO API' }));

app.post('/api/login', wrap(async (req, res) => {
  const login = String(req.body.login || req.body.email || '').trim().toLowerCase();
  const senha = String(req.body.senha || '');
  const chave = (req.ip || '') + '|' + login;
  if (limiteLogin(chave)) falha(429, 'Muitas tentativas. Aguarde 15 minutos.');
  const { rows } = await pool.query('SELECT id, senha_hash, ativo FROM usuarios WHERE lower(login)=$1', [login]);
  const row = rows[0];
  if (!row || !row.ativo || !(await bcrypt.compare(senha, row.senha_hash))) {
    tentativas.get(chave).push(Date.now());
    falha(401, 'E-mail/usuário ou senha incorretos.');
  }
  tentativas.delete(chave);
  const u = await carregarUsuario(row.id);
  if (u.papel !== 'master' && u.hotel_status !== 'ativo') falha(403, mensagemBloqueio(u), { bloqueado: true });
  await pool.query('UPDATE usuarios SET ultimo_login=now() WHERE id=$1', [u.id]);
  const token = jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: '12h' });
  const cfg = u.hotel_id ? await getCfg(u.hotel_id) : null;
  res.json({ token, usuario: perfilPublico(u, cfg) });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const cfg = req.user.hotel_id ? await getCfg(req.user.hotel_id) : null;
  res.json(perfilPublico(req.user, cfg));
}));

app.post('/api/me/senha', auth, wrap(async (req, res) => {
  const { atual, nova } = req.body;
  if (!nova || String(nova).length < 6) falha(400, 'A nova senha precisa ter pelo menos 6 caracteres.');
  const { rows } = await pool.query('SELECT senha_hash FROM usuarios WHERE id=$1', [req.user.id]);
  if (!(await bcrypt.compare(String(atual || ''), rows[0].senha_hash))) falha(400, 'Senha atual incorreta.');
  await pool.query('UPDATE usuarios SET senha_hash=$1 WHERE id=$2', [await bcrypt.hash(String(nova), 10), req.user.id]);
  res.json({ ok: true });
}));

/* ============================== MASTER ============================== */
const master = express.Router();
master.use(auth, soMaster);

master.get('/hoteis', wrap(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT h.*,
      (SELECT count(*) FROM quartos q WHERE q.hotel_id=h.id AND q.ativo) AS qtd_quartos,
      (SELECT count(*) FROM usuarios u WHERE u.hotel_id=h.id AND u.ativo) AS qtd_usuarios,
      (SELECT count(*) FROM reservas r WHERE r.hotel_id=h.id AND r.criado_em > now() - interval '30 days') AS reservas_30d,
      (SELECT max(u.ultimo_login) FROM usuarios u WHERE u.hotel_id=h.id) AS ultimo_acesso
    FROM hoteis h ORDER BY h.nome`);
  res.json(rows);
}));

function camposHotel(b) {
  return {
    nome: txt(b.nome), razao_social: txt(b.razao_social), cnpj: txt(b.cnpj), responsavel: txt(b.responsavel),
    telefone: txt(b.telefone), email: txt(b.email), endereco: txt(b.endereco), cidade: txt(b.cidade),
    uf: txt(b.uf) ? String(b.uf).trim().toUpperCase().slice(0, 2) : null,
    plano: txt(b.plano) || 'Mensal', valor_mensal: num(b.valor_mensal),
    dia_vencimento: Math.min(28, Math.max(1, num(b.dia_vencimento, 10))), observacoes: txt(b.observacoes)
  };
}

master.post('/hoteis', wrap(async (req, res) => {
  const h = camposHotel(req.body);
  if (!h.nome) falha(400, 'Informe o nome do hotel.');
  const adm = req.body.admin || {};
  const admLogin = String(adm.login || '').trim().toLowerCase();
  if (!adm.nome || !admLogin || !adm.senha) falha(400, 'Informe nome, e-mail/usuário e senha do administrador do hotel.');
  if (String(adm.senha).length < 6) falha(400, 'A senha do administrador precisa ter pelo menos 6 caracteres.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const ex = await client.query('SELECT 1 FROM usuarios WHERE lower(login)=$1', [admLogin]);
    if (ex.rows.length) falha(409, 'Já existe um usuário com esse e-mail/login.');
    const cols = Object.keys(h);
    const { rows } = await client.query(
      `INSERT INTO hoteis (${cols.join(',')}) VALUES (${cols.map((_, i) => '$' + (i + 1)).join(',')}) RETURNING *`,
      cols.map(c => h[c]));
    const hotel = rows[0];
    await client.query('INSERT INTO configuracoes (hotel_id, dados) VALUES ($1, $2)', [hotel.id, JSON.stringify({})]);
    await client.query(
      `INSERT INTO usuarios (hotel_id, nome, login, senha_hash, papel) VALUES ($1,$2,$3,$4,'admin')`,
      [hotel.id, String(adm.nome).trim(), admLogin, await bcrypt.hash(String(adm.senha), 10)]);
    await client.query('COMMIT');
    await audit(req, 'Hotel criado', `${hotel.nome} (admin: ${admLogin})`, hotel.id);
    res.status(201).json(hotel);
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));

master.put('/hoteis/:id', wrap(async (req, res) => {
  const h = camposHotel(req.body);
  if (!h.nome) falha(400, 'Informe o nome do hotel.');
  const cols = Object.keys(h);
  const { rows } = await pool.query(
    `UPDATE hoteis SET ${cols.map((c, i) => `${c}=$${i + 1}`).join(',')} WHERE id=$${cols.length + 1} RETURNING *`,
    [...cols.map(c => h[c]), req.params.id]);
  if (!rows[0]) falha(404, 'Hotel não encontrado.');
  await audit(req, 'Hotel atualizado', h.nome, rows[0].id);
  res.json(rows[0]);
}));

master.post('/hoteis/:id/status', wrap(async (req, res) => {
  const status = req.body.status === 'bloqueado' ? 'bloqueado' : 'ativo';
  const motivo = status === 'bloqueado' ? (txt(req.body.motivo) || 'Pendência financeira') : null;
  const { rows } = await pool.query('UPDATE hoteis SET status=$1, motivo_bloqueio=$2 WHERE id=$3 RETURNING *',
    [status, motivo, req.params.id]);
  if (!rows[0]) falha(404, 'Hotel não encontrado.');
  await audit(req, status === 'bloqueado' ? 'Hotel bloqueado' : 'Hotel liberado', motivo || rows[0].nome, rows[0].id);
  res.json(rows[0]);
}));

master.delete('/hoteis/:id', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT nome FROM hoteis WHERE id=$1', [req.params.id]);
  if (!rows[0]) falha(404, 'Hotel não encontrado.');
  if (String(req.body.confirmacao || '').trim() !== rows[0].nome) falha(400, 'Digite o nome exato do hotel para confirmar a exclusão.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const t of ['pagamentos', 'consumos', 'reservas', 'hospedes', 'quartos', 'usuarios', 'configuracoes', 'auditoria'])
      await client.query(`DELETE FROM ${t} WHERE hotel_id=$1`, [req.params.id]);
    await client.query('DELETE FROM hoteis WHERE id=$1', [req.params.id]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  res.json({ ok: true });
}));

master.get('/hoteis/:id/usuarios', wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, nome, login, papel, ativo, ultimo_login, criado_em FROM usuarios WHERE hotel_id=$1 ORDER BY nome', [req.params.id]);
  res.json(rows);
}));

master.post('/hoteis/:id/usuarios', wrap(async (req, res) => {
  const u = await criarUsuario(req.params.id, req.body);
  await audit(req, 'Usuário criado (Master)', `${u.nome} — ${u.papel}`, Number(req.params.id));
  res.status(201).json(u);
}));

master.put('/usuarios/:uid', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1 AND hotel_id IS NOT NULL', [req.params.uid]);
  if (!rows[0]) falha(404, 'Usuário não encontrado.');
  const u = await atualizarUsuario(rows[0], req.body);
  await audit(req, 'Usuário alterado (Master)', u.nome, rows[0].hotel_id);
  res.json(u);
}));

app.use('/api/master', master);

/* ============================== usuários (compartilhado) ============================== */
async function criarUsuario(hotelId, b) {
  const nome = txt(b.nome), login = String(b.login || '').trim().toLowerCase(), senha = String(b.senha || '');
  const papel = PAPEIS_HOTEL.includes(b.papel) ? b.papel : null;
  if (!nome || !login) falha(400, 'Informe nome e e-mail/usuário.');
  if (!papel) falha(400, 'Perfil inválido.');
  if (senha.length < 6) falha(400, 'A senha precisa ter pelo menos 6 caracteres.');
  const ex = await pool.query('SELECT 1 FROM usuarios WHERE lower(login)=$1', [login]);
  if (ex.rows.length) falha(409, 'Esse e-mail/usuário já está em uso.');
  const { rows } = await pool.query(
    `INSERT INTO usuarios (hotel_id, nome, login, senha_hash, papel) VALUES ($1,$2,$3,$4,$5)
     RETURNING id, nome, login, papel, ativo, ultimo_login, criado_em`,
    [hotelId, nome, login, await bcrypt.hash(senha, 10), papel]);
  return rows[0];
}

async function atualizarUsuario(atual, b) {
  const nome = txt(b.nome) || atual.nome;
  const papel = PAPEIS_HOTEL.includes(b.papel) ? b.papel : atual.papel;
  const ativo = b.ativo === undefined ? atual.ativo : !!b.ativo;
  let hash = atual.senha_hash;
  if (b.senha) {
    if (String(b.senha).length < 6) falha(400, 'A senha precisa ter pelo menos 6 caracteres.');
    hash = await bcrypt.hash(String(b.senha), 10);
  }
  const { rows } = await pool.query(
    `UPDATE usuarios SET nome=$1, papel=$2, ativo=$3, senha_hash=$4 WHERE id=$5
     RETURNING id, nome, login, papel, ativo, ultimo_login, criado_em`,
    [nome, papel, ativo, hash, atual.id]);
  return rows[0];
}

/* ============================== HOTEL ============================== */
const api = express.Router();
api.use(auth, doHotel);
const H = req => req.user.hotel_id;

/* ---------- usuários do hotel ---------- */
api.get('/usuarios', pode('usuarios'), wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, nome, login, papel, ativo, ultimo_login, criado_em FROM usuarios WHERE hotel_id=$1 ORDER BY nome', [H(req)]);
  res.json(rows);
}));
api.post('/usuarios', pode('usuarios'), wrap(async (req, res) => {
  const u = await criarUsuario(H(req), req.body);
  await audit(req, 'Usuário criado', `${u.nome} — ${u.papel}`);
  res.status(201).json(u);
}));
api.put('/usuarios/:uid', pode('usuarios'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1 AND hotel_id=$2', [req.params.uid, H(req)]);
  if (!rows[0]) falha(404, 'Usuário não encontrado.');
  if (rows[0].id === req.user.id && (req.body.ativo === false || (req.body.papel && req.body.papel !== 'admin')))
    falha(400, 'Você não pode desativar nem rebaixar o seu próprio usuário.');
  const u = await atualizarUsuario(rows[0], req.body);
  await audit(req, 'Usuário alterado', u.nome);
  res.json(u);
}));

/* ---------- configurações ---------- */
api.get('/config', wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const { rows } = await pool.query('SELECT nome, razao_social, cnpj, telefone, email, endereco, cidade, uf FROM hoteis WHERE id=$1', [H(req)]);
  res.json({ config: cfg, hotel: rows[0] });
}));
api.put('/config', pode('config.editar'), wrap(async (req, res) => {
  const b = req.body.config || {};
  const atual = await getCfg(H(req));
  const lista = (v, def) => Array.isArray(v) ? v.map(x => String(x).trim()).filter(Boolean).slice(0, 40) : def;
  const hora = (v, def) => /^\d{2}:\d{2}$/.test(String(v || '')) ? v : def;
  const novo = {
    checkinHora: hora(b.checkinHora, atual.checkinHora),
    checkoutHora: hora(b.checkoutHora, atual.checkoutHora),
    toleranciaMin: Math.max(0, Math.min(600, num(b.toleranciaMin, atual.toleranciaMin))),
    taxaCheckoutTardio: Math.max(0, num(b.taxaCheckoutTardio, atual.taxaCheckoutTardio)),
    permitirCheckinAntecipado: b.permitirCheckinAntecipado === undefined ? atual.permitirCheckinAntecipado : !!b.permitirCheckinAntecipado,
    bloquearCheckoutComSaldo: b.bloquearCheckoutComSaldo === undefined ? atual.bloquearCheckoutComSaldo : !!b.bloquearCheckoutComSaldo,
    fuso: atual.fuso,
    tiposQuarto: lista(b.tiposQuarto, atual.tiposQuarto),
    formasPagamento: lista(b.formasPagamento, atual.formasPagamento),
    origens: lista(b.origens, atual.origens),
    textoRecibo: txt(b.textoRecibo) ?? atual.textoRecibo
  };
  await pool.query(`INSERT INTO configuracoes (hotel_id, dados) VALUES ($1,$2)
    ON CONFLICT (hotel_id) DO UPDATE SET dados=EXCLUDED.dados`, [H(req), JSON.stringify(novo)]);
  const h = req.body.hotel;
  if (h && txt(h.nome)) {
    await pool.query(`UPDATE hoteis SET nome=$1, razao_social=$2, cnpj=$3, telefone=$4, email=$5, endereco=$6, cidade=$7, uf=$8 WHERE id=$9`,
      [txt(h.nome), txt(h.razao_social), txt(h.cnpj), txt(h.telefone), txt(h.email), txt(h.endereco), txt(h.cidade),
        txt(h.uf) ? String(h.uf).toUpperCase().slice(0, 2) : null, H(req)]);
  }
  await audit(req, 'Configurações alteradas');
  res.json({ config: novo });
}));

/* ---------- quartos ---------- */
function camposQuarto(b, cfg) {
  const q = {
    numero: txt(b.numero), andar: txt(b.andar), tipo: txt(b.tipo) || cfg.tiposQuarto[0] || 'Casal',
    capacidade: Math.max(1, Math.min(20, num(b.capacidade, 2))), preco_diaria: Math.max(0, num(b.preco_diaria)),
    descricao: txt(b.descricao)
  };
  if (!q.numero) falha(400, 'Informe o número do quarto.');
  return q;
}

api.get('/quartos', wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT q.*,
      (SELECT count(*) FROM reservas r WHERE r.quarto_id=q.id) AS qtd_reservas
    FROM quartos q WHERE q.hotel_id=$1 ORDER BY q.ativo DESC, q.andar NULLS LAST, length(q.numero), q.numero`, [H(req)]);
  res.json(rows);
}));

api.post('/quartos', pode('quartos.cadastro'), wrap(async (req, res) => {
  const q = camposQuarto(req.body, await getCfg(H(req)));
  try {
    const { rows } = await pool.query(
      `INSERT INTO quartos (hotel_id, numero, andar, tipo, capacidade, preco_diaria, descricao)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [H(req), q.numero, q.andar, q.tipo, q.capacidade, q.preco_diaria, q.descricao]);
    await audit(req, 'Quarto criado', q.numero);
    res.status(201).json(rows[0]);
  } catch (e) { if (e.code === '23505') falha(409, `Já existe o quarto ${q.numero}.`); throw e; }
}));

api.post('/quartos/lote', pode('quartos.cadastro'), wrap(async (req, res) => {
  const ini = parseInt(req.body.inicio, 10), fim = parseInt(req.body.fim, 10);
  if (!Number.isInteger(ini) || !Number.isInteger(fim) || fim < ini) falha(400, 'Informe a numeração inicial e final.');
  if (fim - ini > 299) falha(400, 'Máximo de 300 quartos por vez.');
  const cfg = await getCfg(H(req));
  const base = camposQuarto({ ...req.body, numero: 'x' }, cfg);
  let criados = 0, pulados = 0;
  for (let n = ini; n <= fim; n++) {
    const r = await pool.query(
      `INSERT INTO quartos (hotel_id, numero, andar, tipo, capacidade, preco_diaria, descricao)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
      [H(req), String(n), base.andar, base.tipo, base.capacidade, base.preco_diaria, base.descricao]);
    r.rowCount ? criados++ : pulados++;
  }
  await audit(req, 'Quartos criados em lote', `${ini} a ${fim} (${criados} criados)`);
  res.json({ criados, pulados });
}));

api.put('/quartos/:id', pode('quartos.cadastro'), wrap(async (req, res) => {
  const q = camposQuarto(req.body, await getCfg(H(req)));
  const ativo = req.body.ativo === undefined ? true : !!req.body.ativo;
  try {
    const { rows } = await pool.query(
      `UPDATE quartos SET numero=$1, andar=$2, tipo=$3, capacidade=$4, preco_diaria=$5, descricao=$6, ativo=$7
       WHERE id=$8 AND hotel_id=$9 RETURNING *`,
      [q.numero, q.andar, q.tipo, q.capacidade, q.preco_diaria, q.descricao, ativo, req.params.id, H(req)]);
    if (!rows[0]) falha(404, 'Quarto não encontrado.');
    await audit(req, 'Quarto alterado', q.numero);
    res.json(rows[0]);
  } catch (e) { if (e.code === '23505') falha(409, `Já existe o quarto ${q.numero}.`); throw e; }
}));

api.delete('/quartos/:id', pode('quartos.cadastro'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT numero FROM quartos WHERE id=$1 AND hotel_id=$2', [req.params.id, H(req)]);
  if (!rows[0]) falha(404, 'Quarto não encontrado.');
  const uso = await pool.query('SELECT count(*) n FROM reservas WHERE quarto_id=$1', [req.params.id]);
  if (uso.rows[0].n > 0) {
    const fut = await pool.query(`SELECT count(*) n FROM reservas WHERE quarto_id=$1 AND status IN ('confirmada','hospedado')`, [req.params.id]);
    if (fut.rows[0].n > 0) falha(400, 'Este quarto tem reservas ativas ou futuras. Transfira-as antes de remover.');
    await pool.query('UPDATE quartos SET ativo=false WHERE id=$1', [req.params.id]);
    await audit(req, 'Quarto desativado', rows[0].numero);
    return res.json({ ok: true, desativado: true });
  }
  await pool.query('DELETE FROM quartos WHERE id=$1', [req.params.id]);
  await audit(req, 'Quarto excluído', rows[0].numero);
  res.json({ ok: true });
}));

api.patch('/quartos/:id/status', pode('quartos.status'), wrap(async (req, res) => {
  const st = ['ok', 'limpeza', 'manutencao'].includes(req.body.status) ? req.body.status : null;
  if (!st) falha(400, 'Status inválido.');
  const { rows } = await pool.query('UPDATE quartos SET status_manual=$1 WHERE id=$2 AND hotel_id=$3 RETURNING *',
    [st, req.params.id, H(req)]);
  if (!rows[0]) falha(404, 'Quarto não encontrado.');
  await audit(req, 'Status do quarto', `${rows[0].numero}: ${st === 'ok' ? 'liberado' : st}`);
  res.json(rows[0]);
}));

/* ---------- situação dos quartos (mapa / governança / painel) ---------- */
async function situacaoQuartos(hotelId, hoje) {
  const q = await pool.query('SELECT * FROM quartos WHERE hotel_id=$1 AND ativo ORDER BY andar NULLS LAST, length(numero), numero', [hotelId]);
  const r = await pool.query(
    `SELECT id, quarto_id, hospede_nome, checkin, checkout, status, valor_total, pago, adultos, criancas
       FROM reservas_v WHERE hotel_id=$1 AND status IN ('confirmada','hospedado') AND checkout >= $2
       ORDER BY checkin`, [hotelId, hoje]);
  return q.rows.map(quarto => {
    const doQuarto = r.rows.filter(x => x.quarto_id === quarto.id);
    const hospedado = doQuarto.find(x => x.status === 'hospedado');
    const chegada = doQuarto.find(x => x.status === 'confirmada' && x.checkin <= hoje && x.checkout > hoje);
    const proxima = doQuarto.find(x => x.status === 'confirmada' && x.checkin > hoje);
    let status = 'disponivel';
    if (hospedado) status = 'ocupado';
    else if (quarto.status_manual === 'manutencao') status = 'manutencao';
    else if (quarto.status_manual === 'limpeza') status = 'limpeza';
    else if (chegada) status = 'reservado';
    const info = x => x && ({
      id: x.id, hospede: x.hospede_nome, checkin: x.checkin, checkout: x.checkout, status: x.status,
      saldo: Math.round((x.valor_total - x.pago) * 100) / 100, pessoas: x.adultos + x.criancas
    });
    return {
      ...quarto, status, atual: info(hospedado), chegada: info(chegada), proxima: info(proxima),
      saida_hoje: !!(hospedado && hospedado.checkout <= hoje),
      chegada_hoje: !!(chegada && chegada.checkin === hoje)
    };
  });
}

api.get('/mapa', wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const hoje = hojeTz(cfg.fuso);
  res.json({ hoje, quartos: await situacaoQuartos(H(req), hoje) });
}));

api.get('/governanca', pode('governanca'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const hoje = hojeTz(cfg.fuso);
  res.json({ hoje, quartos: await situacaoQuartos(H(req), hoje) });
}));

api.post('/governanca/limpar-todos', pode('quartos.status'), wrap(async (req, res) => {
  const r = await pool.query(`UPDATE quartos SET status_manual='ok' WHERE hotel_id=$1 AND status_manual='limpeza'`, [H(req)]);
  await audit(req, 'Governança', `${r.rowCount} quarto(s) liberados de uma vez`);
  res.json({ liberados: r.rowCount });
}));

api.get('/painel', pode('reservas.ver'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const hoje = hojeTz(cfg.fuso);
  const quartos = await situacaoQuartos(H(req), hoje);
  const cont = { disponivel: 0, reservado: 0, ocupado: 0, limpeza: 0, manutencao: 0 };
  quartos.forEach(q => cont[q.status]++);
  const chegadas = await pool.query(
    `SELECT * FROM reservas_v WHERE hotel_id=$1 AND status='confirmada' AND checkin <= $2 AND checkout > $2 ORDER BY checkin, quarto_numero`, [H(req), hoje]);
  const saidas = await pool.query(
    `SELECT * FROM reservas_v WHERE hotel_id=$1 AND status='hospedado' AND checkout <= $2 ORDER BY checkout, quarto_numero`, [H(req), hoje]);
  const naoCompareceu = await pool.query(
    `SELECT * FROM reservas_v WHERE hotel_id=$1 AND status='confirmada' AND checkout <= $2 ORDER BY checkin`, [H(req), hoje]);
  const rec = await pool.query(
    `SELECT COALESCE(SUM(valor) FILTER (WHERE data=$2),0) hoje,
            COALESCE(SUM(valor) FILTER (WHERE date_trunc('month', data)=date_trunc('month', $2::date)),0) mes
       FROM pagamentos WHERE hotel_id=$1 AND NOT estornado`, [H(req), hoje]);
  const hospedesCasa = await pool.query(
    `SELECT COALESCE(SUM(adultos+criancas),0) n FROM reservas WHERE hotel_id=$1 AND status='hospedado'`, [H(req)]);
  const ativos = quartos.filter(q => q.status !== 'manutencao').length;
  res.json({
    hoje, hora: horaTz(cfg.fuso), contagem: cont, total_quartos: quartos.length,
    ocupacao: ativos ? Math.round((cont.ocupado / ativos) * 100) : 0,
    hospedes_casa: hospedesCasa.rows[0].n,
    receita_hoje: rec.rows[0].hoje, receita_mes: rec.rows[0].mes,
    chegadas: chegadas.rows, saidas: saidas.rows, nao_compareceu: naoCompareceu.rows
  });
}));

/* ---------- ocupação (calendário por quarto) ---------- */
api.get('/ocupacao', pode('reservas.ver'), wrap(async (req, res) => {
  const { ini, fim } = req.query;
  if (!dataValida(ini) || !dataValida(fim) || fim < ini) falha(400, 'Período inválido.');
  if (diffDias(ini, fim) > 62) falha(400, 'Período máximo de 62 dias.');
  const q = await pool.query('SELECT id, numero, tipo, andar, capacidade, status_manual FROM quartos WHERE hotel_id=$1 AND ativo ORDER BY andar NULLS LAST, length(numero), numero', [H(req)]);
  const r = await pool.query(
    `SELECT id, quarto_id, hospede_nome, checkin, checkout, status, valor_total, pago FROM reservas_v
      WHERE hotel_id=$1 AND status IN ('confirmada','hospedado','finalizada') AND checkin <= $3 AND checkout > $2`,
    [H(req), ini, fim]);
  res.json({ quartos: q.rows, reservas: r.rows });
}));

/* ---------- disponibilidade por período ---------- */
api.get('/disponibilidade', pode('reservas.ver'), wrap(async (req, res) => {
  const { checkin, checkout } = req.query;
  const ignorar = num(req.query.ignorar_reserva, 0);
  if (!dataValida(checkin) || !dataValida(checkout) || checkout <= checkin) falha(400, 'Datas inválidas.');
  const q = await pool.query('SELECT * FROM quartos WHERE hotel_id=$1 AND ativo ORDER BY andar NULLS LAST, length(numero), numero', [H(req)]);
  const c = await pool.query(
    `SELECT quarto_id, hospede_nome, checkin, checkout FROM reservas_v
      WHERE hotel_id=$1 AND status IN ('confirmada','hospedado') AND id <> $4
        AND NOT (checkout <= $2 OR checkin >= $3)`, [H(req), checkin, checkout, ignorar]);
  res.json(q.rows.map(x => {
    const conflito = c.rows.find(y => y.quarto_id === x.id);
    return { ...x, livre: !conflito, conflito: conflito || null };
  }));
}));

/* ---------- hóspedes ---------- */
function camposHospede(b) {
  const h = {
    nome: txt(b.nome), cpf: soDigitos(b.cpf) || null, documento: txt(b.documento),
    nascimento: dataValida(b.nascimento) ? b.nascimento : null, telefone: txt(b.telefone), email: txt(b.email),
    cidade: txt(b.cidade), uf: txt(b.uf) ? String(b.uf).trim().toUpperCase().slice(0, 2) : null, observacoes: txt(b.observacoes)
  };
  if (!h.nome) falha(400, 'Informe o nome do hóspede.');
  if (h.cpf && !cpfValido(h.cpf)) falha(400, 'CPF inválido. Confira os números digitados.');
  return h;
}

api.get('/hospedes', pode('hospedes.ver'), wrap(async (req, res) => {
  const busca = String(req.query.q || '').trim();
  const dig = soDigitos(busca);
  const limite = Math.min(100, num(req.query.limite, 50));
  const params = [H(req)];
  let where = 'h.hotel_id=$1';
  if (busca) {
    params.push('%' + busca.toLowerCase() + '%');
    let cond = `lower(h.nome) LIKE $${params.length} OR lower(COALESCE(h.email,'')) LIKE $${params.length} OR lower(COALESCE(h.documento,'')) LIKE $${params.length}`;
    if (dig.length >= 3) {
      params.push(dig + '%');
      cond += ` OR h.cpf LIKE $${params.length}`;
      params.push('%' + dig + '%');
      cond += ` OR regexp_replace(COALESCE(h.telefone,''), '\\D', '', 'g') LIKE $${params.length}`;
    }
    where += ` AND (${cond})`;
  }
  params.push(limite);
  const { rows } = await pool.query(`
    SELECT h.*,
      (SELECT count(*) FROM reservas r WHERE r.hospede_id=h.id AND r.status IN ('hospedado','finalizada')) AS estadias,
      (SELECT max(r.checkout) FROM reservas r WHERE r.hospede_id=h.id AND r.status='finalizada') AS ultima_estadia
    FROM hospedes h WHERE ${where}
    ORDER BY ${dig.length === 11 ? '(h.cpf = \'' + dig + '\') DESC,' : ''} h.nome LIMIT $${params.length}`, params);
  const total = await pool.query('SELECT count(*) n FROM hospedes WHERE hotel_id=$1', [H(req)]);
  res.json({ total: total.rows[0].n, itens: rows });
}));

api.get('/hospedes/:id', pode('hospedes.ver'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM hospedes WHERE id=$1 AND hotel_id=$2', [req.params.id, H(req)]);
  if (!rows[0]) falha(404, 'Hóspede não encontrado.');
  const hist = await pool.query(
    `SELECT id, checkin, checkout, status, quarto_numero, valor_total, pago FROM reservas_v
      WHERE hospede_id=$1 ORDER BY checkin DESC LIMIT 50`, [req.params.id]);
  res.json({ ...rows[0], historico: hist.rows });
}));

async function hospedePorCpf(hotelId, cpf, exceto = 0) {
  if (!cpf) return null;
  const { rows } = await pool.query('SELECT id, nome FROM hospedes WHERE hotel_id=$1 AND cpf=$2 AND id<>$3', [hotelId, cpf, exceto]);
  return rows[0] || null;
}

api.post('/hospedes', pode('hospedes.editar'), wrap(async (req, res) => {
  const h = camposHospede(req.body);
  const dup = await hospedePorCpf(H(req), h.cpf);
  if (dup) falha(409, `Já existe hóspede com esse CPF: ${dup.nome}.`, { existente: dup });
  const cols = Object.keys(h);
  const { rows } = await pool.query(
    `INSERT INTO hospedes (hotel_id, ${cols.join(',')}) VALUES ($1, ${cols.map((_, i) => '$' + (i + 2)).join(',')}) RETURNING *`,
    [H(req), ...cols.map(c => h[c])]);
  await audit(req, 'Hóspede cadastrado', h.nome);
  res.status(201).json(rows[0]);
}));

api.put('/hospedes/:id', pode('hospedes.editar'), wrap(async (req, res) => {
  const h = camposHospede(req.body);
  const dup = await hospedePorCpf(H(req), h.cpf, Number(req.params.id));
  if (dup) falha(409, `Já existe hóspede com esse CPF: ${dup.nome}.`, { existente: dup });
  const cols = Object.keys(h);
  const { rows } = await pool.query(
    `UPDATE hospedes SET ${cols.map((c, i) => `${c}=$${i + 1}`).join(',')} WHERE id=$${cols.length + 1} AND hotel_id=$${cols.length + 2} RETURNING *`,
    [...cols.map(c => h[c]), req.params.id, H(req)]);
  if (!rows[0]) falha(404, 'Hóspede não encontrado.');
  await audit(req, 'Hóspede alterado', h.nome);
  res.json(rows[0]);
}));

api.delete('/hospedes/:id', pode('hospedes.excluir'), wrap(async (req, res) => {
  const uso = await pool.query('SELECT count(*) n FROM reservas WHERE hospede_id=$1 AND hotel_id=$2', [req.params.id, H(req)]);
  if (uso.rows[0].n > 0) falha(400, 'Este hóspede possui reservas no histórico e não pode ser excluído.');
  const { rows } = await pool.query('DELETE FROM hospedes WHERE id=$1 AND hotel_id=$2 RETURNING nome', [req.params.id, H(req)]);
  if (!rows[0]) falha(404, 'Hóspede não encontrado.');
  await audit(req, 'Hóspede excluído', rows[0].nome);
  res.json({ ok: true });
}));

/* ---------- reservas ---------- */
async function reservaV(id, hotelId, db = pool) {
  const { rows } = await db.query('SELECT * FROM reservas_v WHERE id=$1 AND hotel_id=$2', [id, hotelId]);
  if (!rows[0]) falha(404, 'Reserva não encontrada.');
  return rows[0];
}

async function checarConflito(db, hotelId, quartoId, ci, co, excetoId = 0) {
  const { rows } = await db.query(
    `SELECT r.id, r.checkin, r.checkout, h.nome FROM reservas r JOIN hospedes h ON h.id=r.hospede_id
      WHERE r.hotel_id=$1 AND r.quarto_id=$2 AND r.status IN ('confirmada','hospedado') AND r.id<>$5
        AND NOT (r.checkout <= $3 OR r.checkin >= $4) LIMIT 1`, [hotelId, quartoId, ci, co, excetoId]);
  if (rows[0]) {
    const f = d => d.split('-').reverse().join('/');
    falha(409, `Quarto ocupado nesse período por ${rows[0].nome} (${f(rows[0].checkin)} a ${f(rows[0].checkout)}).`);
  }
}

api.get('/reservas', pode('reservas.ver'), wrap(async (req, res) => {
  const params = [H(req)];
  let where = 'hotel_id=$1';
  const { status, q, ini, fim } = req.query;
  if (status === 'ativas') where += ` AND status IN ('confirmada','hospedado')`;
  else if (status) { params.push(status); where += ` AND status=$${params.length}`; }
  if (dataValida(ini)) { params.push(ini); where += ` AND checkout >= $${params.length}`; }
  if (dataValida(fim)) { params.push(fim); where += ` AND checkin <= $${params.length}`; }
  if (q) {
    const dig = soDigitos(q);
    params.push('%' + String(q).toLowerCase() + '%');
    let cond = `lower(hospede_nome) LIKE $${params.length} OR lower(quarto_numero) = lower($${params.length + 1})`;
    params.push(String(q).trim());
    if (dig.length >= 3) { params.push(dig + '%'); cond += ` OR hospede_cpf LIKE $${params.length}`; }
    if (/^\d+$/.test(String(q).replace('#', ''))) { params.push(Number(String(q).replace('#', ''))); cond += ` OR id=$${params.length}`; }
    where += ` AND (${cond})`;
  }
  const { rows } = await pool.query(`SELECT * FROM reservas_v WHERE ${where} ORDER BY checkin DESC, id DESC LIMIT 300`, params);
  res.json(rows);
}));

api.get('/reservas/:id', pode('reservas.ver'), wrap(async (req, res) => {
  const r = await reservaV(req.params.id, H(req));
  const c = await pool.query('SELECT * FROM consumos WHERE reserva_id=$1 ORDER BY criado_em', [r.id]);
  const p = await pool.query('SELECT * FROM pagamentos WHERE reserva_id=$1 ORDER BY data, id', [r.id]);
  res.json({ ...r, consumos: c.rows, pagamentos: p.rows });
}));

function camposReserva(b) {
  const r = {
    hospede_id: num(b.hospede_id), quarto_id: num(b.quarto_id), checkin: b.checkin, checkout: b.checkout,
    adultos: Math.max(1, num(b.adultos, 1)), criancas: Math.max(0, num(b.criancas, 0)),
    valor_diaria: Math.max(0, num(b.valor_diaria)), desconto: Math.max(0, num(b.desconto)),
    origem: txt(b.origem) || 'Balcão', observacoes: txt(b.observacoes)
  };
  if (!r.hospede_id) falha(400, 'Selecione o hóspede.');
  if (!r.quarto_id) falha(400, 'Selecione o quarto.');
  if (!dataValida(r.checkin) || !dataValida(r.checkout) || r.checkout <= r.checkin) falha(400, 'Datas inválidas: a saída precisa ser depois da entrada.');
  if (diffDias(r.checkin, r.checkout) > 365) falha(400, 'Período máximo de 365 noites.');
  return r;
}

async function validarQuartoHospede(db, hotelId, r, ignorarCapacidade) {
  const q = await db.query('SELECT * FROM quartos WHERE id=$1 AND hotel_id=$2 AND ativo', [r.quarto_id, hotelId]);
  if (!q.rows[0]) falha(400, 'Quarto inválido.');
  const h = await db.query('SELECT 1 FROM hospedes WHERE id=$1 AND hotel_id=$2', [r.hospede_id, hotelId]);
  if (!h.rows[0]) falha(400, 'Hóspede inválido.');
  if (!ignorarCapacidade && r.adultos + r.criancas > q.rows[0].capacidade)
    falha(409, `O quarto ${q.rows[0].numero} comporta ${q.rows[0].capacidade} pessoa(s).`, { capacidade: true });
  return q.rows[0];
}

api.post('/reservas', pode('reservas.editar'), wrap(async (req, res) => {
  const r = camposReserva(req.body);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [H(req)]);
    const quarto = await validarQuartoHospede(client, H(req), r, req.body.ignorar_capacidade);
    if (!req.body.valor_diaria && req.body.valor_diaria !== 0) r.valor_diaria = quarto.preco_diaria;
    await checarConflito(client, H(req), r.quarto_id, r.checkin, r.checkout);
    const { rows } = await client.query(
      `INSERT INTO reservas (hotel_id, hospede_id, quarto_id, checkin, checkout, adultos, criancas, valor_diaria, desconto, origem, observacoes, criado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      [H(req), r.hospede_id, r.quarto_id, r.checkin, r.checkout, r.adultos, r.criancas, r.valor_diaria, r.desconto, r.origem, r.observacoes, req.user.nome]);
    await client.query('COMMIT');
    const nova = await reservaV(rows[0].id, H(req));
    await audit(req, 'Reserva criada', `#${nova.id} ${nova.hospede_nome} — qto ${nova.quarto_numero} (${nova.checkin} a ${nova.checkout})`);
    res.status(201).json(nova);
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));

api.put('/reservas/:id', pode('reservas.editar'), wrap(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [H(req)]);
    const atual = await reservaV(req.params.id, H(req), client);
    if (['finalizada', 'cancelada', 'no_show'].includes(atual.status)) {
      await client.query('UPDATE reservas SET observacoes=$1 WHERE id=$2', [txt(req.body.observacoes), atual.id]);
    } else {
      const r = camposReserva({ ...atual, ...req.body });
      if (atual.status === 'hospedado' && r.checkin !== atual.checkin) falha(400, 'A data de entrada não pode mudar depois do check-in.');
      await validarQuartoHospede(client, H(req), r, req.body.ignorar_capacidade);
      await checarConflito(client, H(req), r.quarto_id, r.checkin, r.checkout, atual.id);
      await client.query(
        `UPDATE reservas SET hospede_id=$1, quarto_id=$2, checkin=$3, checkout=$4, adultos=$5, criancas=$6,
           valor_diaria=$7, desconto=$8, origem=$9, observacoes=$10 WHERE id=$11`,
        [r.hospede_id, r.quarto_id, r.checkin, r.checkout, r.adultos, r.criancas, r.valor_diaria, r.desconto, r.origem, r.observacoes, atual.id]);
      if (atual.status === 'hospedado' && r.quarto_id !== atual.quarto_id)
        await client.query(`UPDATE quartos SET status_manual='limpeza' WHERE id=$1`, [atual.quarto_id]);
    }
    await client.query('COMMIT');
    const nova = await reservaV(atual.id, H(req));
    const mudancas = [];
    if (nova.quarto_numero !== atual.quarto_numero) mudancas.push(`quarto ${atual.quarto_numero}→${nova.quarto_numero}`);
    if (nova.checkin !== atual.checkin || nova.checkout !== atual.checkout) mudancas.push(`datas ${nova.checkin} a ${nova.checkout}`);
    if (nova.valor_diaria !== atual.valor_diaria) mudancas.push(`diária ${nova.valor_diaria}`);
    if (nova.desconto !== atual.desconto) mudancas.push(`desconto ${nova.desconto}`);
    await audit(req, 'Reserva alterada', `#${nova.id} ${mudancas.join(', ')}`);
    res.json(nova);
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));

api.post('/reservas/:id/checkin', pode('reservas.editar'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const hoje = hojeTz(cfg.fuso);
  const r = await reservaV(req.params.id, H(req));
  if (r.status !== 'confirmada') falha(400, 'Só é possível fazer check-in de reservas confirmadas.');
  if (r.checkin > hoje) falha(400, `Esta reserva começa em ${r.checkin.split('-').reverse().join('/')}. Altere a data de entrada se o hóspede chegou antes.`);
  if (r.checkout <= hoje) falha(400, 'O período desta reserva já terminou. Ajuste a data de saída ou marque como não compareceu.');
  const outro = await pool.query(`SELECT id FROM reservas WHERE quarto_id=$1 AND status='hospedado' AND id<>$2`, [r.quarto_id, r.id]);
  if (outro.rows[0]) falha(409, `O quarto ${r.quarto_numero} ainda está ocupado (reserva #${outro.rows[0].id}). Faça o check-out dela primeiro.`);
  const q = await pool.query('SELECT status_manual FROM quartos WHERE id=$1', [r.quarto_id]);
  if (q.rows[0].status_manual === 'manutencao') falha(409, `O quarto ${r.quarto_numero} está em manutenção. Troque o quarto da reserva.`);
  if (q.rows[0].status_manual === 'limpeza' && !req.body.forcar) falha(409, `O quarto ${r.quarto_numero} ainda está em limpeza.`, { limpeza: true });
  if (!cfg.permitirCheckinAntecipado && r.checkin === hoje && minutos(horaTz(cfg.fuso)) < minutos(cfg.checkinHora))
    falha(400, `Check-in liberado a partir das ${cfg.checkinHora}.`);
  await pool.query(`UPDATE reservas SET status='hospedado', checkin_em=now() WHERE id=$1`, [r.id]);
  await pool.query(`UPDATE quartos SET status_manual='ok' WHERE id=$1`, [r.quarto_id]);
  await audit(req, 'Check-in', `#${r.id} ${r.hospede_nome} — qto ${r.quarto_numero}`);
  res.json(await reservaV(r.id, H(req)));
}));

api.post('/reservas/:id/checkout', pode('reservas.editar'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const r = await reservaV(req.params.id, H(req));
  if (r.status !== 'hospedado') falha(400, 'Só é possível fazer check-out de hóspedes em casa.');
  const taxa = req.body.aplicar_taxa ? cfg.taxaCheckoutTardio : 0;
  const saldo = r.valor_total + taxa - r.pago;
  if (cfg.bloquearCheckoutComSaldo && saldo > 0.009) falha(400, `Existe saldo de R$ ${saldo.toFixed(2).replace('.', ',')}. Registre o pagamento antes do check-out.`);
  await pool.query(`UPDATE reservas SET status='finalizada', checkout_em=now(), taxa_tardia=taxa_tardia+$2 WHERE id=$1`, [r.id, taxa]);
  await pool.query(`UPDATE quartos SET status_manual='limpeza' WHERE id=$1`, [r.quarto_id]);
  await audit(req, 'Check-out', `#${r.id} ${r.hospede_nome} — qto ${r.quarto_numero}${taxa ? ' (taxa tardia)' : ''}${saldo > 0.009 ? ` — saldo em aberto ${saldo.toFixed(2)}` : ''}`);
  res.json(await reservaV(r.id, H(req)));
}));

api.post('/reservas/:id/cancelar', pode('reservas.editar'), wrap(async (req, res) => {
  const r = await reservaV(req.params.id, H(req));
  if (r.status !== 'confirmada') falha(400, 'Só reservas confirmadas (sem check-in) podem ser canceladas.');
  const motivo = txt(req.body.motivo);
  if (!motivo) falha(400, 'Informe o motivo do cancelamento.');
  await pool.query(`UPDATE reservas SET status='cancelada', motivo_cancelamento=$2 WHERE id=$1`, [r.id, motivo]);
  await audit(req, 'Reserva cancelada', `#${r.id} ${r.hospede_nome} — ${motivo}`);
  res.json(await reservaV(r.id, H(req)));
}));

api.post('/reservas/:id/no-show', pode('reservas.editar'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const r = await reservaV(req.params.id, H(req));
  if (r.status !== 'confirmada') falha(400, 'Só reservas confirmadas podem ser marcadas como não compareceu.');
  if (r.checkin > hojeTz(cfg.fuso)) falha(400, 'A data de entrada ainda não chegou.');
  await pool.query(`UPDATE reservas SET status='no_show' WHERE id=$1`, [r.id]);
  await audit(req, 'Não compareceu', `#${r.id} ${r.hospede_nome}`);
  res.json(await reservaV(r.id, H(req)));
}));

api.post('/reservas/:id/reativar', pode('reservas.editar'), wrap(async (req, res) => {
  const r = await reservaV(req.params.id, H(req));
  if (!['cancelada', 'no_show'].includes(r.status)) falha(400, 'Só reservas canceladas ou de não comparecimento podem ser reativadas.');
  await checarConflito(pool, H(req), r.quarto_id, r.checkin, r.checkout, r.id);
  await pool.query(`UPDATE reservas SET status='confirmada', motivo_cancelamento=NULL WHERE id=$1`, [r.id]);
  await audit(req, 'Reserva reativada', `#${r.id} ${r.hospede_nome}`);
  res.json(await reservaV(r.id, H(req)));
}));

api.delete('/reservas/:id', pode('reservas.excluir'), wrap(async (req, res) => {
  const r = await reservaV(req.params.id, H(req));
  if (!['cancelada', 'no_show'].includes(r.status)) falha(400, 'Só é possível excluir reservas canceladas ou de não comparecimento.');
  if (r.pago > 0) falha(400, 'Esta reserva tem pagamentos ativos. Estorne-os antes de excluir.');
  await pool.query('DELETE FROM reservas WHERE id=$1', [r.id]);
  await audit(req, 'Reserva excluída', `#${r.id} ${r.hospede_nome}`);
  res.json({ ok: true });
}));

/* ---------- consumos ---------- */
api.post('/reservas/:id/consumos', pode('consumos.editar'), wrap(async (req, res) => {
  const r = await reservaV(req.params.id, H(req));
  if (['cancelada', 'no_show'].includes(r.status)) falha(400, 'Reserva cancelada não recebe lançamentos.');
  if (r.status === 'finalizada' && !['admin', 'gerente'].includes(req.user.papel)) falha(403, 'Somente gerente/admin lança em conta já fechada.');
  const descricao = txt(req.body.descricao);
  const quantidade = num(req.body.quantidade, 1), valor = num(req.body.valor_unit);
  if (!descricao) falha(400, 'Descreva o item.');
  if (quantidade <= 0 || valor < 0) falha(400, 'Quantidade ou valor inválido.');
  const { rows } = await pool.query(
    `INSERT INTO consumos (hotel_id, reserva_id, descricao, quantidade, valor_unit, lancado_por) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [H(req), r.id, descricao, quantidade, valor, req.user.nome]);
  await audit(req, 'Consumo lançado', `#${r.id} ${quantidade}x ${descricao} (${valor})`);
  res.status(201).json(rows[0]);
}));

api.delete('/consumos/:cid', pode('consumos.editar'), wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.*, r.status FROM consumos c JOIN reservas r ON r.id=c.reserva_id WHERE c.id=$1 AND c.hotel_id=$2`, [req.params.cid, H(req)]);
  if (!rows[0]) falha(404, 'Lançamento não encontrado.');
  if (rows[0].status === 'finalizada' && !['admin', 'gerente'].includes(req.user.papel)) falha(403, 'Somente gerente/admin altera conta já fechada.');
  await pool.query('DELETE FROM consumos WHERE id=$1', [rows[0].id]);
  await audit(req, 'Consumo removido', `#${rows[0].reserva_id} ${rows[0].descricao}`);
  res.json({ ok: true });
}));

/* ---------- pagamentos ---------- */
api.post('/reservas/:id/pagamentos', pode('pagamentos.registrar'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const r = await reservaV(req.params.id, H(req));
  const valor = Math.round(num(req.body.valor) * 100) / 100;
  if (valor <= 0) falha(400, 'Valor inválido.');
  const forma = txt(req.body.forma);
  if (!forma) falha(400, 'Informe a forma de pagamento.');
  const data = dataValida(req.body.data) ? req.body.data : hojeTz(cfg.fuso);
  const { rows } = await pool.query(
    `INSERT INTO pagamentos (hotel_id, reserva_id, valor, forma, data, observacao, registrado_por) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [H(req), r.id, valor, forma, data, txt(req.body.observacao), req.user.nome]);
  await audit(req, 'Pagamento registrado', `#${r.id} ${forma} ${valor.toFixed(2)}`);
  res.status(201).json(rows[0]);
}));

api.post('/pagamentos/:pid/estornar', pode('pagamentos.estornar'), wrap(async (req, res) => {
  const motivo = txt(req.body.motivo);
  if (!motivo) falha(400, 'Informe o motivo do estorno.');
  const { rows } = await pool.query(
    `UPDATE pagamentos SET estornado=true, motivo_estorno=$1 WHERE id=$2 AND hotel_id=$3 AND NOT estornado RETURNING *`,
    [motivo, req.params.pid, H(req)]);
  if (!rows[0]) falha(404, 'Pagamento não encontrado ou já estornado.');
  await audit(req, 'Pagamento estornado', `#${rows[0].reserva_id} ${rows[0].forma} ${rows[0].valor} — ${motivo}`);
  res.json(rows[0]);
}));

/* ---------- financeiro ---------- */
api.get('/financeiro', pode('financeiro.ver'), wrap(async (req, res) => {
  const cfg = await getCfg(H(req));
  const hoje = hojeTz(cfg.fuso);
  const { situacao, q } = req.query;
  const params = [H(req)];
  let where = `hotel_id=$1 AND status IN ('confirmada','hospedado','finalizada')`;
  if (situacao === 'pendente') where += ' AND pago <= 0.009 AND valor_total > 0.009';
  if (situacao === 'parcial') where += ' AND pago > 0.009 AND valor_total - pago > 0.009';
  if (situacao === 'pago') where += ' AND valor_total - pago <= 0.009';
  if (situacao === 'aberto') where += ' AND valor_total - pago > 0.009';
  if (q) { params.push('%' + String(q).toLowerCase() + '%'); where += ` AND lower(hospede_nome) LIKE $${params.length}`; }
  const lista = await pool.query(`SELECT * FROM reservas_v WHERE ${where} ORDER BY (valor_total - pago) DESC, checkin DESC LIMIT 300`, params);
  const resumo = await pool.query(`
    SELECT
      (SELECT COALESCE(SUM(valor),0) FROM pagamentos WHERE hotel_id=$1 AND NOT estornado AND data=$2) AS recebido_hoje,
      (SELECT COALESCE(SUM(valor),0) FROM pagamentos WHERE hotel_id=$1 AND NOT estornado AND date_trunc('month',data)=date_trunc('month',$2::date)) AS recebido_mes,
      (SELECT COALESCE(SUM(GREATEST(valor_total-pago,0)),0) FROM reservas_v WHERE hotel_id=$1 AND status IN ('hospedado','finalizada')) AS a_receber_casa,
      (SELECT COALESCE(SUM(GREATEST(valor_total-pago,0)),0) FROM reservas_v WHERE hotel_id=$1 AND status='finalizada') AS em_atraso`,
    [H(req), hoje]);
  res.json({ resumo: resumo.rows[0], reservas: lista.rows });
}));

api.get('/pagamentos', pode('financeiro.ver'), wrap(async (req, res) => {
  const { ini, fim, forma } = req.query;
  if (!dataValida(ini) || !dataValida(fim)) falha(400, 'Período inválido.');
  const params = [H(req), ini, fim];
  let where = 'p.hotel_id=$1 AND p.data BETWEEN $2 AND $3';
  if (forma) { params.push(forma); where += ` AND p.forma=$${params.length}`; }
  const { rows } = await pool.query(
    `SELECT p.*, h.nome AS hospede_nome, q.numero AS quarto_numero FROM pagamentos p
       JOIN reservas r ON r.id=p.reserva_id JOIN hospedes h ON h.id=r.hospede_id JOIN quartos q ON q.id=r.quarto_id
      WHERE ${where} ORDER BY p.data DESC, p.id DESC`, params);
  res.json(rows);
}));

/* ---------- relatório gerencial ---------- */
api.get('/relatorio', pode('relatorios.ver'), wrap(async (req, res) => {
  const { ini, fim } = req.query;
  if (!dataValida(ini) || !dataValida(fim) || fim < ini) falha(400, 'Período inválido.');
  const dias = diffDias(ini, fim) + 1;
  if (dias > 400) falha(400, 'Período máximo de 400 dias.');
  const fimExcl = somaDias(fim, 1);
  const quartos = await pool.query('SELECT count(*) n FROM quartos WHERE hotel_id=$1 AND ativo', [H(req)]);
  const reservas = await pool.query(
    `SELECT id, checkin, checkout, valor_diaria, desconto, noites, origem, quarto_tipo, status, adultos, criancas, criado_em
       FROM reservas_v WHERE hotel_id=$1 AND status IN ('confirmada','hospedado','finalizada')
        AND checkin < $3 AND checkout > $2`, [H(req), ini, fimExcl]);
  const canceladas = await pool.query(
    `SELECT status, count(*) n FROM reservas WHERE hotel_id=$1 AND status IN ('cancelada','no_show') AND checkin BETWEEN $2 AND $3 GROUP BY status`,
    [H(req), ini, fim]);
  const pags = await pool.query(
    `SELECT forma, SUM(valor) total, count(*) n FROM pagamentos WHERE hotel_id=$1 AND NOT estornado AND data BETWEEN $2 AND $3 GROUP BY forma ORDER BY total DESC`,
    [H(req), ini, fim]);
  const cons = await pool.query(
    `SELECT COALESCE(SUM(c.quantidade*c.valor_unit),0) total FROM consumos c JOIN reservas r ON r.id=c.reserva_id
      WHERE c.hotel_id=$1 AND r.status IN ('hospedado','finalizada') AND c.criado_em::date BETWEEN $2 AND $3`, [H(req), ini, fim]);

  let noites = 0, receitaDiarias = 0, hospedes = 0;
  const porOrigem = {}, porTipo = {}, porDia = {};
  for (let i = 0; i < dias; i++) porDia[somaDias(ini, i)] = 0;
  for (const r of reservas.rows) {
    const a = r.checkin > ini ? r.checkin : ini;
    const b = r.checkout < fimExcl ? r.checkout : fimExcl;
    const n = Math.max(0, diffDias(a, b));
    const diariaLiquida = r.noites ? (r.valor_diaria * r.noites - r.desconto) / r.noites : 0;
    const valor = n * diariaLiquida;
    noites += n; receitaDiarias += valor; hospedes += r.adultos + r.criancas;
    for (let i = 0; i < n; i++) porDia[somaDias(a, i)]++;
    const o = r.origem || 'Não informado';
    porOrigem[o] = porOrigem[o] || { reservas: 0, noites: 0, valor: 0 };
    porOrigem[o].reservas++; porOrigem[o].noites += n; porOrigem[o].valor += valor;
    const t = r.quarto_tipo || '—';
    porTipo[t] = porTipo[t] || { reservas: 0, noites: 0, valor: 0 };
    porTipo[t].reservas++; porTipo[t].noites += n; porTipo[t].valor += valor;
  }
  const capacidade = quartos.rows[0].n * dias;
  res.json({
    ini, fim, dias, quartos: quartos.rows[0].n, capacidade,
    reservas: reservas.rows.length, noites, hospedes,
    ocupacao: capacidade ? Math.round((noites / capacidade) * 1000) / 10 : 0,
    receita_diarias: Math.round(receitaDiarias * 100) / 100,
    receita_consumos: cons.rows[0].total,
    diaria_media: noites ? Math.round((receitaDiarias / noites) * 100) / 100 : 0,
    revpar: capacidade ? Math.round((receitaDiarias / capacidade) * 100) / 100 : 0,
    recebido: pags.rows.reduce((s, p) => s + p.total, 0),
    por_forma: pags.rows,
    por_origem: Object.entries(porOrigem).map(([k, v]) => ({ nome: k, ...v })).sort((a, b) => b.valor - a.valor),
    por_tipo: Object.entries(porTipo).map(([k, v]) => ({ nome: k, ...v })).sort((a, b) => b.valor - a.valor),
    por_dia: Object.entries(porDia).map(([d, n]) => ({ data: d, ocupados: n })),
    canceladas: canceladas.rows.find(x => x.status === 'cancelada')?.n || 0,
    no_show: canceladas.rows.find(x => x.status === 'no_show')?.n || 0
  });
}));

/* ---------- auditoria ---------- */
api.get('/auditoria', pode('auditoria'), wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM auditoria WHERE hotel_id=$1 ORDER BY criado_em DESC LIMIT $2', [H(req), Math.min(500, num(req.query.limite, 200))]);
  res.json(rows);
}));

app.use('/api', api);

/* ============================== erros ============================== */
app.use((req, res) => res.status(404).json({ erro: 'Rota não encontrada.' }));
app.use((err, req, res, next) => {
  if (err instanceof Erro) return res.status(err.status).json({ erro: err.message, ...(err.extra || {}) });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ erro: 'Dados inválidos.' });
  console.error(err);
  res.status(500).json({ erro: 'Erro interno no servidor.' });
});

/* ============================== inicialização ============================== */
async function garantirMaster() {
  const login = String(process.env.MASTER_EMAIL || '').trim().toLowerCase();
  const senha = process.env.MASTER_PASSWORD;
  if (!login || !senha) { console.warn('Aviso: MASTER_EMAIL/MASTER_PASSWORD não definidos — nenhum usuário Master criado.'); return; }
  const hash = await bcrypt.hash(String(senha), 10);
  const nome = process.env.MASTER_NOME || 'Administrador Master';
  const ex = await pool.query('SELECT id FROM usuarios WHERE lower(login)=$1', [login]);
  if (ex.rows[0]) await pool.query(`UPDATE usuarios SET senha_hash=$1, papel='master', hotel_id=NULL, ativo=true WHERE id=$2`, [hash, ex.rows[0].id]);
  else await pool.query(`INSERT INTO usuarios (hotel_id, nome, login, senha_hash, papel) VALUES (NULL,$1,$2,$3,'master')`, [nome, login, hash]);
  console.log('Usuário Master pronto:', login);
}

(async () => {
  await migrate();
  await garantirMaster();
  app.listen(PORT, () => console.log(`Hotel Manager PRO API rodando na porta ${PORT}`));
})().catch(e => { console.error('Falha ao iniciar:', e); process.exit(1); });
