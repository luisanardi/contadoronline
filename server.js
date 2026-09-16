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

// Libera todos os arquivos HTML, CSS e JS para a web
app.use(express.static(__dirname));

// Garante que a raiz do site abra o index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Garante que as pastas de upload existam no servidor
const uploadDir = path.join(__dirname, 'uploads', 'guias');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configuração do Banco de Dados PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Criar tabelas automaticamente caso não existam
const initDB = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS Empresas (
                ID SERIAL PRIMARY KEY,
                CNPJ VARCHAR(14) UNIQUE NOT NULL,
                RazaoSocial VARCHAR(255) NOT NULL,
                SenhaHash VARCHAR(255) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Tributos (
                ID SERIAL PRIMARY KEY,
                EmpresaID INT REFERENCES Empresas(ID),
                TipoImposto VARCHAR(50) NOT NULL,
                Competencia VARCHAR(7) NOT NULL,
                Valor DECIMAL(10,2) NOT NULL,
                DataVencimento DATE NOT NULL,
                PixCopiaECola TEXT,
                CaminhoPDF VARCHAR(255)
            );
        `);
        console.log('Tabelas sincronizadas com sucesso no PostgreSQL!');
    } catch (err) {
        console.error('Erro ao inicializar tabelas do banco de dados:', err);
    }
};
initDB();

const CHAVE_SECRETA_JWT = process.env.JWT_SECRET || "sua_chave_secreta_super_segura";

// Configuração para Salvamento de PDFs enviados pelo Contador
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Servir a pasta de uploads para download seguro dos PDFs
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==========================================
// ROTA 1: LOGIN DA EMPRESA (CLIENTE)
// ==========================================
app.post('/api/login', async (req, res) => {
    const { cnpj, senha } = req.body;
    if (!cnpj || !senha) return res.status(400).json({ erro: 'CNPJ e senha são obrigatórios.' });

    const cnpjLimpo = cnpj.replace(/\D/g, '');

    try {
        const result = await pool.query('SELECT * FROM Empresas WHERE CNPJ = $1', [cnpjLimpo]);
        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'CNPJ ou senha inválidos.' });
        }

        const empresa = result.rows[0];
        const senhaValida = await bcrypt.compare(senha, empresa.senhahash);
        if (!senhaValida) {
            return res.status(401).json({ erro: 'CNPJ ou senha inválidos.' });
        }

        const token = jwt.sign(
            { id: empresa.id, cnpj: empresa.cnpj, razaoSocial: empresa.razaosocial },
            CHAVE_SECRETA_JWT,
            { expiresIn: '8h' }
        );

        res.json({
            mensagem: 'Login realizado com sucesso!',
            token,
            empresa: { id: empresa.id, cnpj: empresa.cnpj, razaoSocial: empresa.razaosocial }
        });
    } catch (err) {
        res.status(500).json({ erro: 'Erro interno no servidor.' });
    }
});

// ==========================================
// ROTA 2: PAINEL DO CLIENTE (LISTAR IMPOSTOS)
// ==========================================
app.get('/api/meus-impostos', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, CHAVE_SECRETA_JWT, async (err, decoded) => {
        if (err) return res.status(403).json({ erro: 'Sessão expirada ou inválida.' });

        try {
            const tributos = await pool.query(
                'SELECT * FROM Tributos WHERE EmpresaID = $1 ORDER BY DataVencimento ASC',
                [decoded.id]
            );
            res.json(tributos.rows);
        } catch (error) {
            res.status(500).json({ erro: 'Erro ao buscar impostos.' });
        }
    });
});

// ==========================================
// ROTA 3: ENVIO DE GUIA PELO CONTADOR (ADMIN)
// ==========================================
app.post('/api/tributos/publicar', upload.single('pdf_file'), async (req, res) => {
    const { cnpj, tipoImposto, competencia, valor, vencimento, pix } = req.body;
    if (!cnpj) return res.status(400).json({ erro: 'CNPJ é obrigatório.' });

    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const caminhoPDF = req.file ? req.file.path : null;

    try {
        const empresaRes = await pool.query('SELECT id FROM Empresas WHERE CNPJ = $1', [cnpjLimpo]);
        if (empresaRes.rows.length === 0) {
            return res.status(404).json({ erro: 'Empresa com este CNPJ não está cadastrada.' });
        }

        const empresaId = empresaRes.rows[0].id;
        const sql = `
            INSERT INTO Tributos (EmpresaID, TipoImposto, Competencia, Valor, DataVencimento, PixCopiaECola, CaminhoPDF)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        await pool.query(sql, [empresaId, tipoImposto, competencia, valor, vencimento, pix, caminhoPDF]);

        res.status(201).json({ mensagem: 'Guia cadastrada e disponibilizada com sucesso!' });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao salvar a guia de imposto.' });
    }
});

// Porta dinâmica para o Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API executando na porta ${PORT}`));
