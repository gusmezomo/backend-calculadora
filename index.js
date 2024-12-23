const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const usersFile = path.join(__dirname, 'users.json');
const secretKey = 'supersecretkey'; // Substitua por uma chave mais segura

app.use(cors());
app.use(express.json());

function loadUsers() {
    if (!fs.existsSync(usersFile)) {
        fs.writeFileSync(usersFile, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}

function saveUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Usuário e senha são obrigatórios' });
    }

    const users = loadUsers();
    const userExists = users.find(user => user.username === username);

    if (userExists) {
        return res.status(400).json({ message: 'Usuário já existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword, notas: [] });
    saveUsers(users);

    res.json({ message: 'Usuário registrado com sucesso!' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Usuário e senha são obrigatórios' });
    }

    const users = loadUsers();
    const user = users.find(user => user.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.json({ message: 'Login bem-sucedido', token });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded.username;
        next();
    } catch {
        return res.status(401).json({ message: 'Token inválido ou expirado' });
    }
}

app.post('/salvar-notas', authenticate, (req, res) => {
    const { cadeira, grauA, grauB, semestre } = req.body;

    if (!cadeira || isNaN(grauA) || isNaN(grauB) || !semestre) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
    }

    const users = loadUsers();
    const user = users.find(user => user.username === req.user);

    user.notas.push({ cadeira, grauA, grauB, semestre });
    saveUsers(users);

    res.json({ message: 'Notas salvas com sucesso!', notas: user.notas });
});

app.get('/listar-notas', authenticate, (req, res) => {
    const users = loadUsers();
    const user = users.find(user => user.username === req.user);

    res.json(user.notas);
});

app.delete('/excluir-nota/:index', authenticate, (req, res) => {
    const index = parseInt(req.params.index);

    if (isNaN(index)) {
        return res.status(400).json({ message: 'Índice inválido' });
    }

    const users = loadUsers();
    const user = users.find(user => user.username === req.user);

    if (!user || index < 0 || index >= user.notas.length) {
        return res.status(404).json({ message: 'Nota não encontrada' });
    }

    user.notas.splice(index, 1); // Remove a nota pelo índice
    saveUsers(users);

    res.json({ message: 'Nota excluída com sucesso!' });
});

app.get('/', (req, res) => {
    res.send('Servidor está funcionando! Use as rotas /register, /login, /salvar-notas, /listar-notas e /excluir-nota/:index.');
});

app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
