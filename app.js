require('dotenv').config();

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const upload = require('./UploadConfig');

const mongoURL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5001;

app.use(express.json());
app.use('/uploads', express.static('uploads'));
mongoose
    .connect(mongoURL)
    .then(() => {
        console.log("Database Connect!");
    })
    .catch((e) => {
        console.log(e);
    });

require('./UserDetails');
const User = mongoose.model("UserInfo");

app.get("/", (req, res) => {
    res.send({ status: "Started" });
});

app.post('/SignUpForm', upload.single('profileImage'), async (req, res) => {
    console.log(req.file);
    const { username, email, telephone, password } = req.body;
    const profileImage = req.file ? req.file.path : null;

    const oldUser = await User.findOne({ email: email });

    if (oldUser) {
        return res.send({ data: "User already exists!!" });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    try {
        await User.create({
            username: username,
            email: email,
            telephone: telephone,
            password: encryptedPassword,
            profileImage: profileImage
        });
        res.send({ status: "ok", data: "User Created" });
    } catch (error) {
        res.send({ status: "error", data: error });
    }
});

app.post("/LoginForm", async (req, res) => {
    const { email, password } = req.body;
    const oldUser = await User.findOne({ email: email });

    if (!oldUser) {
        return res.send({ data: "Usuário não existe" });
    }

    if (await bcrypt.compare(password, oldUser.password)) {
        const token = jwt.sign({ email: oldUser.email }, JWT_SECRET);
        console.log(token);

        return res.send({
            status: "ok",
            data: token,
            userType: oldUser.userType,
        });
    } else {
        return res.send({ error: "error" });
    }
});

app.post("/userdata", async (req, res) => {
    const { token } = req.body;
    try {
        const user = jwt.verify(token, JWT_SECRET);
        const useremail = user.email;

        User.findOne({ email: useremail }).then((data) => {
            return res.send({ status: "ok", data: data });
        });
    } catch (error) {
        return res.send({ error: error });
    }
});

app.put('/updateuser', upload.single('profileImage'), async (req, res) => {
    const authHeader = req.headers.authorization;
  
    // Verifique se o token está presente
    if (!authHeader) {
      return res.status(401).send({ error: 'Token não fornecido' });
    }
  
    const token = authHeader.split(' ')[1]; // Extraia o token do formato "Bearer <token>"
  
    try {
      // Decodifique o token
      const decoded = jwt.verify(token, JWT_SECRET);
      const { email } = decoded;
  
      // Encontre o usuário pelo email
      const user = await User.findOne({ email: email });
      if (!user) {
        return res.status(404).send({ error: 'Usuário não encontrado' });
      }
  
      // Atualize os dados do usuário
      const { username, telephone, password } = req.body;
      if (username) user.username = username;
      if (telephone) user.telephone = telephone;
      if (password) user.password = await bcrypt.hash(password, 10);
      if (req.file) user.profileImage = req.file.path;
  
      // Salve as alterações
      await user.save();
  
      res.status(200).send({ message: 'Dados do usuário atualizados com sucesso' });
    } catch (error) {
      res.status(500).send({ error: 'Erro ao atualizar os dados do usuário', details: error.message });
    }
  });
  

app.listen(PORT, () => {
    console.log(`Node Js server started on port ${PORT}!`);
});
