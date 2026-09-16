const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Serve os arquivos HTML/CSS/JS que estão na mesma pasta do server.js
app.use(express.static(__dirname));

// Configuração do Banco de Dados PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_super_segura';

// ==========================================
// ROTA DE CADASTRO DO CONTADOR
// ==========================================
app.post('/api/contador/cadastro', async (req, res) => {
    try {
        let { nomeEscritorio, email, senha } = req.body;
        if (!nomeEscritorio || !email || !senha) {
            return res.status(400).json({ erro: 'Preencha todos os campos.' });
        }

        email = email.trim().toLowerCase();

        const usuarioExiste = await pool.query('SELECT * FROM contadores WHERE LOWER(email) = $1', [email]);
        if (usuarioExiste.rows.length > 0) {
            return res.status(400).json({ erro: 'Este e-mail já está cadastrado. Faça login ou recupere a senha.' });
        }

        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        // Insere preenchendo tanto 'senha' quanto 'senhahash' para evitar qualquer restrição do banco
        await pool.query(
            'INSERT INTO contadores (nomeescritorio, email, senha, senhahash) VALUES ($1, $2, $3, $4)',
            [nomeEscritorio, email, senhaHash, senhaHash]
        );

        res.status(201).json({ mensagem: 'Cadastro realizado com sucesso!' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

// ==========================================
// ROTA DE LOGIN DO CONTADOR
// ==========================================
app.post('/api/contador/login', async (req, res) => {
    try {
        let { email, senha } = req.body;
        if (!email || !senha) {
            return res.status(400).json({ erro: 'Preencha o e-mail e a senha.' });
        }

        email = email.trim().toLowerCase();

        const resultado = await pool.query('SELECT * FROM contadores WHERE LOWER(email) = $1', [email]);
        if (resultado.rows.length === 0) {
            return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
        }

        const contador = resultado.rows[0];
        const senhaArmazenada = contador.senhahash || contador.senha;

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
            token: token,
            nomeEscritorio: contador.nomeescritorio || 'Escritório',
            contador: {
                nomeEscritorio: contador.nomeescritorio || 'Escritório'
            }
        });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

// ==========================================
// ROTA DE RECUPERAÇÃO / REDEFINIÇÃO DE SENHA
// ==========================================
app.post('/api/contador/esqueci-senha', async (req, res) => {
    try {
        let { email, novaSenha } = req.body;
        if (!email || !novaSenha) {
            return res.status(400).json({ erro: 'Informe o e-mail e a nova senha.' });
        }

        email = email.trim().toLowerCase();

        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(novaSenha, salt);

        // Atualiza ambas as colunas para garantir compatibilidade total
        const atualizacao = await pool.query(
            'UPDATE contadores SET senha = $1, senhahash = $2 WHERE LOWER(email) = $3',
            [senhaHash, senhaHash, email]
        );

        if (atualizacao.rowCount === 0) {
            return res.status(404).json({ erro: 'E-mail não encontrado no sistema.' });
        }

        res.json({ mensagem: 'Senha redefinida com sucesso! Agora você pode fazer login.' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

// Inicialização do Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
