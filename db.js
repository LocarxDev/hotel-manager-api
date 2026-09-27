// Conexão com o Postgres + criação/atualização automática das tabelas
const { Pool, types } = require('pg');

// DATE volta como texto 'YYYY-MM-DD' (evita bug de fuso) e NUMERIC como número
types.setTypeParser(1082, v => v);
types.setTypeParser(1700, v => (v === null ? null : parseFloat(v)));
types.setTypeParser(20, v => (v === null ? null : parseInt(v, 10)));

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('ERRO: variável DATABASE_URL não definida.');
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  ssl: /localhost|127\.0\.0\.1|railway\.internal/.test(connectionString) ? false : { rejectUnauthorized: false },
  max: 10
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS hoteis (
  id SERIAL PRIMARY KEY,
  nome TEXT NOT NULL,
  razao_social TEXT,
  cnpj TEXT,
  responsavel TEXT,
  telefone TEXT,
  email TEXT,
  endereco TEXT,
  cidade TEXT,
  uf TEXT,
  plano TEXT DEFAULT 'Mensal',
  valor_mensal NUMERIC(10,2) DEFAULT 0,
  dia_vencimento INT DEFAULT 10,
  status TEXT NOT NULL DEFAULT 'ativo',
  motivo_bloqueio TEXT,
  observacoes TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  hotel_id INT REFERENCES hoteis(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  login TEXT NOT NULL,
  senha_hash TEXT NOT NULL,
  papel TEXT NOT NULL,
  ativo BOOLEAN NOT NULL DEFAULT true,
  ultimo_login TIMESTAMPTZ,
  criado_em TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS usuarios_login_uk ON usuarios (lower(login));

CREATE TABLE IF NOT EXISTS configuracoes (
  hotel_id INT PRIMARY KEY REFERENCES hoteis(id) ON DELETE CASCADE,
  dados JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS quartos (
  id SERIAL PRIMARY KEY,
  hotel_id INT NOT NULL REFERENCES hoteis(id) ON DELETE CASCADE,
  numero TEXT NOT NULL,
  andar TEXT,
  tipo TEXT NOT NULL,
  capacidade INT NOT NULL DEFAULT 2,
  preco_diaria NUMERIC(10,2) NOT NULL DEFAULT 0,
  descricao TEXT,
  status_manual TEXT NOT NULL DEFAULT 'ok',
  ativo BOOLEAN NOT NULL DEFAULT true,
  criado_em TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS quartos_numero_uk ON quartos (hotel_id, lower(numero));

CREATE TABLE IF NOT EXISTS hospedes (
  id SERIAL PRIMARY KEY,
  hotel_id INT NOT NULL REFERENCES hoteis(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  cpf TEXT,
  documento TEXT,
  nascimento DATE,
  telefone TEXT,
  email TEXT,
  cidade TEXT,
  uf TEXT,
  observacoes TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS hospedes_cpf_uk ON hospedes (hotel_id, cpf) WHERE cpf IS NOT NULL AND cpf <> '';
CREATE INDEX IF NOT EXISTS hospedes_nome_idx ON hospedes (hotel_id, lower(nome));

CREATE TABLE IF NOT EXISTS reservas (
  id SERIAL PRIMARY KEY,
  hotel_id INT NOT NULL REFERENCES hoteis(id) ON DELETE CASCADE,
  hospede_id INT NOT NULL REFERENCES hospedes(id),
  quarto_id INT NOT NULL REFERENCES quartos(id),
  checkin DATE NOT NULL,
  checkout DATE NOT NULL,
  adultos INT NOT NULL DEFAULT 1,
  criancas INT NOT NULL DEFAULT 0,
  valor_diaria NUMERIC(10,2) NOT NULL DEFAULT 0,
  desconto NUMERIC(10,2) NOT NULL DEFAULT 0,
  taxa_tardia NUMERIC(10,2) NOT NULL DEFAULT 0,
  origem TEXT DEFAULT 'Balcão',
  observacoes TEXT,
  status TEXT NOT NULL DEFAULT 'confirmada',
  motivo_cancelamento TEXT,
  checkin_em TIMESTAMPTZ,
  checkout_em TIMESTAMPTZ,
  criado_por TEXT,
  criado_em TIMESTAMPTZ DEFAULT now(),
  CHECK (checkout > checkin)
);
CREATE INDEX IF NOT EXISTS reservas_periodo_idx ON reservas (hotel_id, quarto_id, checkin, checkout);

CREATE TABLE IF NOT EXISTS consumos (
  id SERIAL PRIMARY KEY,
  hotel_id INT NOT NULL REFERENCES hoteis(id) ON DELETE CASCADE,
  reserva_id INT NOT NULL REFERENCES reservas(id) ON DELETE CASCADE,
  descricao TEXT NOT NULL,
  quantidade NUMERIC(10,2) NOT NULL DEFAULT 1,
  valor_unit NUMERIC(10,2) NOT NULL DEFAULT 0,
  lancado_por TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pagamentos (
  id SERIAL PRIMARY KEY,
  hotel_id INT NOT NULL REFERENCES hoteis(id) ON DELETE CASCADE,
  reserva_id INT NOT NULL REFERENCES reservas(id) ON DELETE CASCADE,
  valor NUMERIC(10,2) NOT NULL,
  forma TEXT NOT NULL,
  data DATE NOT NULL,
  observacao TEXT,
  estornado BOOLEAN NOT NULL DEFAULT false,
  motivo_estorno TEXT,
  registrado_por TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pagamentos_data_idx ON pagamentos (hotel_id, data);

CREATE TABLE IF NOT EXISTS auditoria (
  id SERIAL PRIMARY KEY,
  hotel_id INT REFERENCES hoteis(id) ON DELETE CASCADE,
  usuario_id INT,
  usuario_nome TEXT,
  acao TEXT NOT NULL,
  detalhe TEXT,
  criado_em TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auditoria_hotel_idx ON auditoria (hotel_id, criado_em DESC);

CREATE OR REPLACE VIEW reservas_v AS
SELECT r.*,
  (r.checkout - r.checkin) AS noites,
  h.nome AS hospede_nome, h.cpf AS hospede_cpf, h.telefone AS hospede_telefone,
  h.email AS hospede_email, h.observacoes AS hospede_obs,
  q.numero AS quarto_numero, q.tipo AS quarto_tipo, q.andar AS quarto_andar,
  COALESCE(c.total, 0) AS consumos_total,
  COALESCE(p.total, 0) AS pago,
  ((r.checkout - r.checkin) * r.valor_diaria - r.desconto + r.taxa_tardia + COALESCE(c.total, 0)) AS valor_total
FROM reservas r
JOIN hospedes h ON h.id = r.hospede_id
JOIN quartos q ON q.id = r.quarto_id
LEFT JOIN (SELECT reserva_id, SUM(quantidade * valor_unit) AS total FROM consumos GROUP BY reserva_id) c ON c.reserva_id = r.id
LEFT JOIN (SELECT reserva_id, SUM(valor) AS total FROM pagamentos WHERE NOT estornado GROUP BY reserva_id) p ON p.reserva_id = r.id;
`;

async function migrate() {
  await pool.query(SCHEMA);
}

module.exports = { pool, migrate };
