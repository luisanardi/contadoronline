const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Configuração do Banco de Dados PostgreSQL (Certifique-se de que a variável DATABASE_URL está configurada no Render)
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

        // Padroniza o e-mail para minúsculas e remove espaços para evitar erros futuros
        email = email.trim().toLowerCase();

        // Verifica se já existe
        const usuarioExiste = await pool.query('SELECT * FROM contadores WHERE LOWER(email) = $1', [email]);
        if (usuarioExiste.rows.length > 0) {
            return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
        }

        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);

        await pool.query(
            'INSERT INTO contadores (nomeescritorio, email, senha) VALUES ($1, $2, $3)',
            [nomeEscritorio, email, senhaHash]
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

        // Limpeza automática: converte para minúsculas e remove espaços
        email = email.trim().toLowerCase();

        const resultado = await pool.query('SELECT * FROM contadores WHERE LOWER(email) = $1', [email]);
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
            token: token,
            nomeEscritorio: contador.nomeescritorio || 'Escritório',
            nome_escritorio: contador.nomeescritorio || 'Escritório',
            contador: {
                nomeEscritorio: contador.nomeescritorio || 'Escritório',
                nome_escritorio: contador.nomeescritorio || 'Escritório'
            }
        });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro interno no servidor: ' + erro.message });
    }
});

// Inicialização do Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
