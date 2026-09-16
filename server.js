const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jwt-simple');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors());

// Serve os arquivos estáticos (HTML, CSS, JS) da raiz
app.use(express.static(__dirname));

// Configuração da conexão com o banco PostgreSQL no Render
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Chave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_padrao_contador';

// Configuração do Multer para upload de arquivos
const upload = multer({ dest: 'uploads/' });

// ==========================================
// ROTA MAIN: Abre o index.html na raiz do site
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==========================================
// ROTA 0: CADASTRO DE EMPRESA
// ==========================================
app.post('/api/cadastrar-empresa', async (req, res) => {
    const { cnpj, razaoSocial, senha } = req.body;

    if (!cnpj || !razaoSocial || !senha) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios.' });
    }

    const cnpjLimpo = cnpj.replace(/\D/g, '');

    try {
        // Verifica se o CNPJ já está cadastrado
        const empresaExistente = await pool.query('SELECT * FROM Empresas WHERE CNPJ = $1', [cnpjLimpo]);
        if (empresaExistente.rows.length > 0) {
            return res.status(400).json({ erro: 'CNPJ já cadastrado no sistema.' });
        }

        // Criptografa a senha antes de salvar no banco
        const senhaHash = await bcrypt.hash(senha, 10);

        // Insere a nova empresa no banco PostgreSQL
        await pool.query(
            'INSERT INTO Empresas (CNPJ, RazaoSocial, SenhaHash) VALUES ($1, $2, $3)',
            [cnpjLimpo, razaoSocial, senhaHash]
        );

        res.status(201).json({ mensagem: 'Empresa cadastrada com sucesso!' });
    } catch (err) {
        console.error('Erro no cadastro:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar empresa.' });
    }
});

// ==========================================
// ROTA 1: LOGIN DA EMPRESA
// ==========================================
app.post('/api/login', async (req, res) => {
    const { cnpj, senha } = req.body;
    const cnpjLimpo = cnpj ? cnpj.replace(/\D/g, '') : '';

    try {
        const result = await pool.query('SELECT * FROM Empresas WHERE CNPJ = $1', [cnpjLimpo]);
        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const empresa = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, empresa.senhahash);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const token = jwt.encode({ id: empresa.id, cnpj: empresa.cnpj }, JWT_SECRET);

        res.json({
            sucesso: true,
            token: token,
            empresa: {
                cnpj: empresa.cnpj,
                razaoSocial: empresa.razaosocial
            }
        });
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ erro: 'Erro interno no servidor.' });
    }
});

// ==========================================
// ROTA 2: BUSCAR IMPOSTOS DA EMPRESA (PAINEL)
// ==========================================
app.get('/api/meus-impostos', async (req, res) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ erro: 'Acesso não autorizado. Faça login novamente.' });
    }

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        const result = await pool.query(
            'SELECT * FROM Tributos WHERE EmpresaID = $1 ORDER BY DataVencimento ASC',
            [decoded.id]
        );

        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar impostos:', err);
        res.status(401).json({ erro: 'Sessão inválida ou expirada.' });
    }
});

// ==========================================
// ROTA 3: PUBLICAR GUIA DE IMPOSTO (PAINEL ADMIN)
// ==========================================
app.post('/api/tributos/publicar', upload.single('arquivoPdf'), async (req, res) => {
    const { cnpj, mesReferencia, tipoImposto, valor, dataVencimento, codigoPix } = req.body;

    const cnpjLimpo = cnpj ? cnpj.replace(/\D/g, '') : '';

    try {
        const empresaResult = await pool.query('SELECT id FROM Empresas WHERE CNPJ = $1', [cnpjLimpo]);
        if (empresaResult.rows.length === 0) {
            return res.status(404).json({ erro: 'Empresa com este CNPJ não foi encontrada.' });
        }

        const empresaId = empresaResult.rows[0].id;
        let caminhoPdf = null;

        if (req.file) {
            caminhoPdf = req.file.path;
        }

        await pool.query(
            `INSERT INTO Tributos (EmpresaID, MesReferencia, TipoImposto, Valor, DataVencimento, CodigoPix, CaminhoPDF)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [empresaId, mesReferencia, tipoImposto, valor, dataVencimento, codigoPix, caminhoPdf]
        );

        res.status(201).json({ mensagem: 'Guia de imposto cadastrada com sucesso!' });
    } catch (err) {
        console.error('Erro ao publicar imposto:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar imposto.' });
    }
});

// ==========================================
// CRIAÇÃO AUTOMÁTICA DAS TABELAS NO BANCO
// ==========================================
const initDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS Empresas (
                ID SERIAL PRIMARY KEY,
                CNPJ VARCHAR(20) UNIQUE NOT NULL,
                RazaoSocial VARCHAR(255) NOT NULL,
                SenhaHash VARCHAR(255) NOT NULL,
                DataCriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS Tributos (
                ID SERIAL PRIMARY KEY,
                EmpresaID INT REFERENCES Empresas(ID) ON DELETE CASCADE,
                MesReferencia VARCHAR(20) NOT NULL,
                TipoImposto VARCHAR(100) NOT NULL,
                Valor NUMERIC(10,2) NOT NULL,
                DataVencimento DATE NOT NULL,
                CodigoPix TEXT,
                CaminhoPDF VARCHAR(255),
                StatusPagamento VARCHAR(20) DEFAULT 'Pendente',
                DataCriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Tabelas sincronizadas com sucesso no PostgreSQL!');
    } catch (err) {
        console.error('Erro ao inicializar banco de dados:', err);
    }
};

initDatabase();

// Inicialização do servidor na porta dinâmica do Render
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`API executando na porta ${PORT}`);
});
