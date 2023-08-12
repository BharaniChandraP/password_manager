if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
  }
  //process.env holds various environmental variables for the current process
  // const fs = require('fs');
  const express = require('express')
  const keys = require('./keys'); 
  const app = express()
  const bcrypt = require('bcrypt')
  const passport = require('passport')
  const flash = require('express-flash')
  const session = require('express-session')
  const cookieSession=require('cookie-session')
  const methodOverride = require('method-override')
  const User = require('./models/users')
  const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'myDefaultEncryptionKey';
  // const Project = require('./models/projects');
   const mongoose = require('mongoose');
  const initializePassport = require('./passport-config')
  initializePassport(
    passport,
    email => User.findOne({email: email}),
    id => User.findById(id)
  )
  // const dayjs = require('dayjs');
  const bodyParser = require('body-parser');
// const { decrypt } = require('dotenv');



  app.set('view-engine', 'ejs')
  app.use(express.urlencoded({ extended: false }))
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(flash())
  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }))
  app.use(passport.initialize())
  app.use(passport.session())
  app.use(methodOverride('_method'))
  const sessionConfig = {
    secret: 'thisshouldbeabettersecret!',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7, 
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
  }
  app.use(session(sessionConfig))
  // app.use('/uploads', express.static('uploads'));
  app.get('/', checkAuthenticated, (req, res) => {
    res.render('home.ejs', { name: req.user.name })
  })



  app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
  })
  
  app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }))
  
  app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
  })
  
  app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
            const user = new User({
                name: req.body.name,
                email: req.body.email,
                password: hashedPassword
                });
                await user.save();
                console.log(user);
                res.redirect('/login');
      
    } catch(error){
        console.log(error);
      res.redirect('/register')
    }
  })
  
  
  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next()
    }
  
    res.redirect('/login')
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect('/')
    }
    next()
  }
  function encrypt(text) {
    const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }
  
  // Function to decrypt an encrypted string
  // function decrypt(text) {
  //   const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
  //   let decrypted = decipher.update(text, 'hex', 'utf8');
  //   decrypted += decipher.final('utf8');
  //   return decrypted;
  // }

  function decrypt(encrypted) {
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
app.get('/', checkAuthenticated, (req, res) => {
  res.render('home.ejs', {
    name: req.user.name,
    passwords: req.user.passwords,
    // decrypt
  });
});

  app.post('/', checkAuthenticated, async (req, res) => {
    const { topic, password } = req.body;
  
    try {
      const encryptedPassword = encrypt(password);
  
      const user = await User.findById(req.user._id);
      user.passwords.push({ topic, password: encryptedPassword });
      await user.save();
      res.redirect('/');
    } catch (error) {
      console.error(error);
      res.redirect('/');
    }
  });
  
  app.post('/', checkAuthenticated, async (req, res) => {
    const { application, username, password } = req.body;
  
    try {
      const user = await User.findById(req.user._id);
      user.passwords.push({ application, username, password });
      await user.save();
      res.redirect('/');
    } catch (error) {
      console.error(error);
      res.redirect('/');
    }
  });
  app.get('/', checkAuthenticated, (req, res) => {
    res.render('home.ejs', { 
      name: req.user.name,
      passwords: req.user.passwords
    });
  });
  app.get('/passwords', checkAuthenticated, (req, res) => {
    res.render('passwords.ejs', {name: req.user.name, passwords: req.user.passwords });
});

  
    
 
app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});


  function connectDB() {
    const dbURI = 'mongodb+srv://bharanichandra1104:T30m1GLgj05uibdD@cluster0.inppxms.mongodb.net/?retryWrites=true&w=majority';
  
    mongoose.connect(dbURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
    .then(() => {
      console.log('MongoDB Connected...');
      startServer();
    })
    .catch(err => {
      console.error('Failed to connect to MongoDB:', err);
    });
  }
  // Check if already connected to MongoDB Atlas
  if (mongoose.connection.readyState === 1) {
      // Already connected, start the server
      startServer();
    } else {
      // Not connected, establish connection and then start the server
      connectDB();
    }
    

const PORT = process.env.NODE_ENV || 8080;
function startServer() {
        app.listen(PORT, () => {
          console.log('Server started on port 8080');
        });
      }