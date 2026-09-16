const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'seredo_super_seguro_contador';

// Configuração do Banco de Dados PostgreSQL (Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Configuração do Nodemailer para envio de e-mails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Configuração do Multer para upload de arquivos em memória (PDFs)
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// Inicialização e atualização automática das tabelas e colunas no PostgreSQL
async function iniciarBanco() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS contadores (
                id SERIAL PRIMARY KEY,
                nomeescritorio VARCHAR(255),
                email VARCHAR(255) UNIQUE NOT NULL,
                senha VARCHAR(255),
                senhahash VARCHAR(255),
                datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS empresas (
                id SERIAL PRIMARY KEY,
                contador_id INTEGER REFERENCES contadores(id) ON DELETE CASCADE,
                cnpj VARCHAR(30) UNIQUE NOT NULL,
                razaosocial VARCHAR(255) NOT NULL,
                emailempresa VARCHAR(255),
                senha VARCHAR(255),
                senhahash VARCHAR(255),
                datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS guias (
                id SERIAL PRIMARY KEY,
                cnpj VARCHAR(30) NOT NULL,
                tipoimposto VARCHAR(50) NOT NULL,
                competencia VARCHAR(20) NOT NULL,
                valor NUMERIC(12, 2) NOT NULL,
                vencimento DATE NOT NULL,
                pix TEXT,
                arquivonome VARCHAR(255),
                arquivodados BYTEA,
                arquivotipo VARCHAR(100),
                datacriacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            ALTER TABLE contadores ADD COLUMN IF NOT EXISTS senha VARCHAR(255);
            ALTER TABLE contadores ADD COLUMN IF NOT EXISTS senhahash VARCHAR(255);
            ALTER TABLE contadores ADD COLUMN IF NOT EXISTS nomeescritorio VARCHAR(255);
            
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS contador_id INTEGER;
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS senha VARCHAR(255);
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS senhahash VARCHAR(255);
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS razaosocial VARCHAR(255);
            ALTER TABLE empresas ADD COLUMN IF NOT EXISTS emailempresa VARCHAR(255);
            
            ALTER TABLE empresas ALTER COLUMN senha DROP NOT NULL;
            ALTER TABLE empresas ALTER COLUMN senhahash DROP NOT NULL;
            ALTER TABLE empresas ALTER COLUMN cnpj TYPE VARCHAR(30);

            ALTER TABLE guias ALTER COLUMN cnpj TYPE VARCHAR(30);
        `);

        console.log("Banco de dados sincronizado com sucesso!");
    } catch (erro) {
        console.error("Erro ao inicializar o banco de dados:", erro);
    }
}

iniciarBanco();

// Middleware de Autenticação JWT
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ erro: 'Token não fornecido.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ erro: 'Token mal formatado.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ erro: 'Token inválido ou expirado.' });
        }
        req.contadorId = decoded.id;
        req.empresaCnpj = decoded.cnpj;
        next();
    });
}

// ==================== ROTAS DE CONTADORES ====================

app.post('/api/contador/cadastro', async (req, res) => {
    try {
        const { nomeEscritorio, email, senha } = req.body;
        if (!nomeEscritorio || !email || !senha) {
            return res.status(400).json({ erro: 'Preencha todos os campos.' });
        }

        const hashSenha = await bcrypt.hash(senha, 10);
        
        const resultado = await pool.query(
            'INSERT INTO contadores (nomeescritorio, email, senha, senhahash) VALUES ($1, $2, $3, $3) RETURNING id, nomeescritorio, email',
            [nomeEscritorio, email, hashSenha]
        );

        res.status(201).json({ 
            mensagem: 'Escritório cadastrado com sucesso!', 
            contador: {
                id: resultado.rows[0].id,
                nomeEscritorio: resultado.rows[0].nomeescritorio,
                email: resultado.rows[0].email
            } 
        });
    } catch (erro) {
        if (erro.code === '23505') {
            return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
        }
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

app.post('/api/contador/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        if (!email || !senha) {
            return res.status(400).json({ erro: 'Preencha o e-mail e a senha.' });
        }

        const resultado = await pool.query('SELECT * FROM contadores WHERE email = $1', [email]);
        if (resultado.rows.length === 0) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        const contador = resultado.rows[0];
        const senhaArmazenada = contador.senha || contador.senhahash;

        if (!senhaArmazenada) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        const senhaValida = await bcrypt.compare(senha, senhaArmazenada);
        if (!senhaValida) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        const token = jwt.sign({ id: contador.id, email: contador.email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            mensagem: 'Login realizado com sucesso!',
            token,
            nomeEscritorio: contador.nomeescritorio || 'Escritório Contábil',
            nome_escritorio: contador.nomeescritorio || 'Escritório Contábil'
        });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

// ==================== ROTAS DE EMPRESAS ====================

app.get('/api/empresas', verificarToken, async (req, res) => {
    try {
        const resultado = await pool.query(
            'SELECT id, cnpj, razaosocial, emailempresa, datacriacao FROM empresas WHERE contador_id = $1 ORDER BY datacriacao DESC',
            [req.contadorId]
        );
        res.json(resultado.rows);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao listar empresas: ' + erro.message });
    }
});

// Cadastro de empresa pelo Contador
app.post('/api/cadastrar-empresa', verificarToken, async (req, res) => {
    try {
        let { cnpj, razaoSocial, emailEmpresa, senha } = req.body;
        if (!cnpj || !razaoSocial) {
            return res.status(400).json({ erro: 'Preencha o CNPJ e a Razão Social.' });
        }

        cnpj = cnpj.trim();
        
        let senhaHash = null;
        if (senha) {
            senhaHash = await bcrypt.hash(senha, 10);
        }

        await pool.query(
            'INSERT INTO empresas (contador_id, cnpj, razaosocial, emailempresa, senha, senhahash) VALUES ($1, $2, $3, $4, $5, $5)',
            [req.contadorId, cnpj, razaoSocial, emailEmpresa, senhaHash]
        );

        res.status(201).json({ mensagem: 'Empresa cadastrada com sucesso!' });
    } catch (erro) {
        if (erro.code === '23505') {
            return res.status(400).json({ erro: 'Este CNPJ já está cadastrado.' });
        }
        res.status(500).json({ erro: 'Erro ao cadastrar empresa: ' + erro.message });
    }
});

app.delete('/api/empresas/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const empresa = await pool.query('SELECT * FROM empresas WHERE id = $1 AND contador_id = $2', [id, req.contadorId]);
        if (empresa.rows.length === 0) {
            return res.status(404).json({ erro: 'Empresa não encontrada.' });
        }

        const cnpj = empresa.rows[0].cnpj;
        await pool.query('DELETE FROM guias WHERE cnpj = $1', [cnpj]);
        await pool.query('DELETE FROM empresas WHERE id = $1', [id]);

        res.json({ mensagem: 'Empresa excluída com sucesso!' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao excluir empresa: ' + erro.message });
    }
});

// ==================== LOGIN E PRIMEIRO ACESSO DO CLIENTE ====================

// Rota para definir senha (Primeiro Acesso)
app.post('/api/empresa/definir-senha', async (req, res) => {
    try {
        let { cnpj, novaSenha } = req.body;
        if (!cnpj || !novaSenha) {
            return res.status(400).json({ erro: 'Informe o CNPJ e a nova senha.' });
        }

        cnpj = cnpj.trim();
        const resultado = await pool.query('SELECT * FROM empresas WHERE cnpj = $1', [cnpj]);

        if (resultado.rows.length === 0) {
            return res.status(404).json({ erro: 'CNPJ não encontrado. Verifique com seu contador se sua empresa já foi cadastrada.' });
        }

        const senhaHash = await bcrypt.hash(novaSenha, 10);

        await pool.query(
            'UPDATE empresas SET senha = $1, senhahash = $1 WHERE cnpj = $2',
            [senhaHash, cnpj]
        );

        res.json({ mensagem: 'Senha cadastrada com sucesso! Agora você já pode fazer login.' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao definir senha: ' + erro.message });
    }
});

// Login do Cliente/Empresa
app.post('/api/empresa/login', async (req, res) => {
    try {
        let { cnpj, senha } = req.body;
        if (!cnpj || !senha) {
            return res.status(400).json({ erro: 'Informe o CNPJ e a senha.' });
        }

        cnpj = cnpj.trim();
        const resultado = await pool.query('SELECT * FROM empresas WHERE cnpj = $1', [cnpj]);

        if (resultado.rows.length === 0) {
            return res.status(400).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const empresa = resultado.rows[0];
        const senhaArmazenada = empresa.senha || empresa.senhahash;

        if (!senhaArmazenada) {
            return res.status(400).json({ erro: 'Esta empresa ainda não possui senha cadastrada.' });
        }

        const senhaValida = await bcrypt.compare(senha, senhaArmazenada);
        if (!senhaValida) {
            return res.status(400).json({ erro: 'CNPJ ou senha incorretos.' });
        }

        const token = jwt.sign({ id: empresa.id, cnpj: empresa.cnpj }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            mensagem: 'Login realizado com sucesso!',
            token,
            razaoSocial: empresa.razaosocial,
            cnpj: empresa.cnpj
        });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro no login: ' + erro.message });
    }
});

// Listar guias para a empresa logada
app.get('/api/empresa/guias', verificarToken, async (req, res) => {
    try {
        const cnpjConsulta = req.empresaCnpj;
        if (!cnpjConsulta) {
            return res.status(400).json({ erro: 'CNPJ não identificado no token.' });
        }

        const guias = await pool.query(
            'SELECT id, tipoimposto, competencia, valor, vencimento, pix, arquivonome, arquivotipo FROM guias WHERE cnpj = $1 ORDER BY vencimento DESC',
            [cnpjConsulta]
        );
        res.json(guias.rows);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao buscar guias: ' + erro.message });
    }
});

// Download do PDF da Guia
app.get('/api/empresa/guias/download/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const resultado = await pool.query(
            'SELECT arquivonome, arquivotipo, arquivodados FROM guias WHERE id = $1',
            [id]
        );

        if (resultado.rows.length === 0 || !resultado.rows[0].arquivodados) {
            return res.status(404).json({ erro: 'Arquivo PDF não encontrado.' });
        }

        const guia = resultado.rows[0];
        res.setHeader('Content-Type', guia.arquivotipo || 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${guia.arquivonome || 'guia.pdf'}"`);
        res.send(guia.arquivodados);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao baixar o arquivo: ' + erro.message });
    }
});

// ==================== ROTAS DE GUIAS (CONTADOR) ====================

app.post('/api/guias', verificarToken, upload.single('arquivoPdf'), async (req, res) => {
    try {
        let { cnpj, tipoImposto, competencia, valor, vencimento, pix } = req.body;
        const arquivo = req.file;

        if (!cnpj || !tipoImposto || !competencia || !valor || !vencimento || !arquivo) {
            return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios e envie o PDF.' });
        }

        cnpj = cnpj.trim();
        const valorTratado = parseFloat(valor);

        await pool.query(
            `INSERT INTO guias (cnpj, tipoimposto, competencia, valor, vencimento, pix, arquivonome, arquivodados, arquivotipo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
                cnpj, 
                tipoImposto, 
                competencia, 
                valorTratado, 
                vencimento, 
                pix || '', 
                arquivo.originalname, 
                arquivo.buffer, 
                arquivo.mimetype
            ]
        );

        res.status(201).json({ mensagem: 'Guia cadastrada e enviada com sucesso!' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao salvar guia: ' + erro.message });
    }
});

app.listen(PORT, () => {
    console.log(`API executando na porta ${PORT}`);
});
