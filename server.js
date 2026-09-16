const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors());

// Serve os arquivos estáticos da raiz
app.use(express.static(__dirname));

// Libera o acesso público aos arquivos PDF salvos na pasta uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuração da conexão com o banco PostgreSQL no Render
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_padrao_contador';
const upload = multer({ dest: 'uploads/' });

// Rota Principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Cadastro de Empresa
app.post('/api/cadastrar-empresa', async (req, res) => {
    const { cnpj, razaoSocial, senha } = req.body;

    if (!cnpj || !razaoSocial || !senha) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios.' });
    }

    const cnpjLimpo = cnpj.replace(/\D/g, '');

    try {
        const empresaExistente = await pool.query('SELECT * FROM empresas WHERE cnpj = $1', [cnpjLimpo]);
        if (empresaExistente.rows.length > 0) {
            return res.status(400).json({ erro: 'CNPJ já cadastrado no sistema.' });
        }

        const senhaHash = await bcrypt.hash(senha, 10);

        await pool.query(
            'INSERT INTO empresas (cnpj, razaosocial, senhahash) VALUES ($1, $2, $3)',
            [cnpjLimpo, razaoSocial, senhaHash]
        );

        res.status(201).json({ mensagem: 'Empresa cadastrada com sucesso!' });
    } catch (err) {
        console.error('Erro no cadastro:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar empresa.' });
    }
});

// Login da Empresa
app.post('/api/login', async (req, res) => {
    const { cnpj, senha } = req.body;
    const cnpjLimpo = cnpj ? cnpj.replace(/\D/g, '') : '';

    try {
        const result = await pool.query('SELECT * FROM empresas WHERE cnpj = $1', [cnpjLimpo]);
        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const empresa = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, empresa.senhahash);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const token = jwt.sign({ id: empresa.id, cnpj: empresa.cnpj }, JWT_SECRET, { expiresIn: '8h' });

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

// Buscar Impostos da Empresa (Painel do Cliente)
app.get('/api/meus-impostos', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Acesso não autorizado. Faça login novamente.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query(
            'SELECT * FROM tributos WHERE empresaid = $1 ORDER BY datavencimento ASC',
            [decoded.id]
        );

        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar impostos:', err);
        res.status(401).json({ erro: 'Sessão inválida ou expirada.' });
    }
});

// ==========================================
// ROTAS PARA O PAINEL DO CONTADOR
// ==========================================

// Listar todas as empresas cadastradas (Painel Admin)
app.get('/api/empresas', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, cnpj, razaosocial, datacriacao FROM empresas ORDER BY razaosocial ASC');
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao listar empresas:', err);
        res.status(500).json({ erro: 'Erro ao buscar empresas.' });
    }
});

// Listar tributos de uma empresa específica pelo CNPJ (Painel Admin)
app.get('/api/tributos/empresa/:cnpj', async (req, res) => {
    const { cnpj } = req.params;
    const cnpjLimpo = cnpj.replace(/\D/g, '');

    try {
        const empresaResult = await pool.query('SELECT id FROM empresas WHERE cnpj = $1', [cnpjLimpo]);
        if (empresaResult.rows.length === 0) {
            return res.status(404).json({ erro: 'Empresa não encontrada.' });
        }

        const empresaId = empresaResult.rows[0].id;
        const result = await pool.query('SELECT * FROM tributos WHERE empresaid = $1 ORDER BY datavencimento ASC', [empresaId]);
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar tributos da empresa:', err);
        res.status(500).json({ erro: 'Erro ao buscar guias.' });
    }
});

// Publicar Guia de Imposto (Painel Admin)
app.post('/api/tributos/publicar', upload.single('arquivoPdf'), async (req, res) => {
    const { cnpj, mesReferencia, tipoImposto, valor, dataVencimento, codigoPix } = req.body;
    const cnpjLimpo = cnpj ? cnpj.replace(/\D/g, '') : '';

    try {
        const empresaResult = await pool.query('SELECT id FROM empresas WHERE cnpj = $1', [cnpjLimpo]);
        if (empresaResult.rows.length === 0) {
            return res.status(404).json({ erro: 'Empresa com este CNPJ não foi encontrada.' });
        }

        const empresaId = empresaResult.rows[0].id;
        let caminhoPdf = req.file ? req.file.path : null;

        await pool.query(
            `INSERT INTO tributos (empresaid, mesreferencia, tipoimposto, valor, datavencimento, codigopix, caminhopdf)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [empresaId, mesReferencia, tipoImposto, valor, dataVencimento, codigoPix, caminhoPdf]
        );

        res.status(201).json({ mensagem: 'Guia de imposto cadastrada com sucesso!' });
    } catch (err) {
        console.error('Erro ao publicar imposto:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar imposto.' });
    }
});

// Deletar Guia de Imposto (Painel Admin)
app.delete('/api/tributos/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const tributoResult = await pool.query('SELECT caminhopdf FROM tributos WHERE id = $1', [id]);
        
        if (tributoResult.rows.length === 0) {
            return res.status(404).json({ erro: 'Guia não encontrada.' });
        }

        const caminhoPdf = tributoResult.rows[0].caminhopdf;

        if (caminhopdf && fs.existsSync(caminhopdf)) {
            fs.unlinkSync(caminhopdf);
        }

        await pool.query('DELETE FROM tributos WHERE id = $1', [id]);

        res.json({ mensagem: 'Guia deletada com sucesso!' });
    } catch (err) {
        console.error('Erro ao deletar guia:', err);
        res.status(500).json({ erro: 'Erro ao deletar guia no servidor.' });
    }
});

// Inicialização e Migração Segura do Banco de Dados
const initDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS empresas (
                id SERIAL PRIMARY KEY,
                cnpj VARCHAR(20) UNIQUE NOT NULL,
                razaosocial VARCHAR(255) NOT NULL,
                senhahash VARCHAR(255) NOT NULL,
                datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS tributos (
                id SERIAL PRIMARY KEY,
                empresaid INT REFERENCES empresas(id) ON DELETE CASCADE,
                mesreferencia VARCHAR(20) NOT NULL,
                tipoimposto VARCHAR(100) NOT NULL,
                valor NUMERIC(10,2) NOT NULL,
                datavencimento DATE NOT NULL,
                codigopix TEXT,
                caminhopdf VARCHAR(255),
                statuspagamento VARCHAR(20) DEFAULT 'Pendente',
                datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Garante que a coluna datacriacao exista caso a tabela já estivesse criada sem ela
        await pool.query(`
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
        `);

        console.log('Tabelas verificadas, migradas e sincronizadas com sucesso no PostgreSQL!');
    } catch (err) {
        console.error('Erro ao inicializar banco de dados:', err);
    }
};

initDatabase();

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`API executando na porta ${PORT}`);
});
