const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'my_secret';
const users = [];
const {rateLimit} = require('express-rate-limit')

const limiter = rateLimit({
	windowMs: 60 * 1000, // 1 min
	limit: 8, 
	standardHeaders: 'draft-8',
	legacyHeaders: false, 
})





function authorizeRole(role) {
  return (req, res, next) => {
    if (!role.includes(req.user.role)) return res.sendStatus(403);

    next();
  };
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;

    next();
  });
}

router.post('/register',limiter, async (req, res) => {
  const { username,email, password, role } = req.body;
  let emailReg = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if(!emailReg.test(email)) res.status(403).json({message:'Incorrect email'})
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ username, password: hashedPassword, role: role || 'user' });

  res.json({ message: 'User registered' });
});


router.get('/public', (req, res) => {
  res.send(`Hello welcome to public area!`);
});

router.post('/login',limiter, async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(403).json({ message: 'Invalid password' });

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET);

  res.json({ token });
});

router.use(authenticateToken);

router.get("/profile",(req,res)=>{
    res.send(req.user);
})

router.get('/protected', (req, res) => {
  res.send(`welcome to protected area!`);
});


router.get('/admin',authorizeRole(['admin']), (req, res) => {
  res.send('Welcome to the admin panel.');
});


router.get('/moderator',authorizeRole(['admin','moderator']), (req, res) => {
  res.send('Welcome to the moderator panel.');
});


router.put('/users/:id/:role',authorizeRole(['admin']),(req,res)=>{
    users[req.params.id].role = req.params.role;
    res.send("user updated");
})

router.put('/profile',(req,res)=>{
    for(i=0;i<users.length;i++){
        if(users[i].email == req.email){
            users[i].email = req.email || users[i].email;
            users[i].username = req.username || users[i].username;
            users[i].password = req.password || users[i].password;
        }
    }
    res.send("user updated");
})


module.exports = router;