require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bycrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const users = [];

const verifyToken = (req, res, next)  => {
  const token = req.headers.authorization;
  //console.log('authHeader in verifyToken middleware:', authHeader);
  if(!token) return res.status(401).json({message : 'access denied to this user'});
  //const token = authHeader.split(' ')[1]; 
  try{
     const verified = jwt.verify(token , process.env.JWT_SECRET);
     req.user = verified;
     next();
  }catch(err){
    console.error('error occurred in verifyToken ',err);
    return res.status(500).json({message : 'internal server error'});
  }
}

app.post('/signUp' , async (req , res ) => {
  try{
    const { username , password} = req.body;
    const hashedPassword = await bycrypt.hash(password,10);
    const user =  { username , password: hashedPassword} ;
    users.push(user);
    res.status(201).json({message : 'user created successfully'});

  }catch(err){
    console.error('error occurred during signup',err);
    return res.status(500).json({message : 'internal server error'});
  }
})

app.post('/signIn' , async (req , res) => {
  try{

    const {username , password } = req.body;
    const user = users.find(user => user.username === username);
    if(!user) return res.status(404).json({message : 'user not found'});
    const validPassword  = await bycrypt.compare(password, user.password);
    if(!validPassword) return res.status(400).json({message : 'invalid password'});
    const token = jwt.sign({username : user.username} , process.env.JWT_SECRET);
    res.status(200).json({message : 'sign in successful', token : token});

  }catch(err){
    console.error('error occurred during signIn', err);
    return res.status(500).json({message : 'internal server error'});
  }
})

app.get('/profile' , verifyToken, async (req , res) => {
  try{
      res.send('Welcome to your profile, ' + req.user.username);
  }catch(err) {
    console.error('error occurred in /profile route' , err);
    return res.status(500).json({message : 'internal server error'});
  }
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
