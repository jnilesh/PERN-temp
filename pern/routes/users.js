var express = require('express');
var router = express.Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
var passport = require('passport');

/* GET users listing. */
router.get('/',auth, function(req, res, next) {
// console.log(req.user)
  
  pool.query("select * from users")
  .then(result => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.json({status: 'all users!',cuser: req.user.user_id, user: result.rows});
  })
  .catch((err) => next(err));
  
});

router.post('/signup',notAuth, async (req, res, next) => {
  let { name, email, password, password2 } = req.body;


  console.log({
    name,
    email,
    password,
    password2
  });

  if (!name || !email || !password || !password2) {
    var err = new Error("Please enter all fields");
      err.status = 403;
      next(err); 
  }

  else if (password.length < 6) {
    var err = new Error("Password must be a least 6 characters long");
      err.status = 403;
      next(err); 
  }

  else if (password !== password2) {
    var err = new Error("Passwords do not match");
      err.status = 403;
      next(err); 
  }else{
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
  

  pool.query("select * from users where user_email =  $1",[req.body.email])
  .then(result => {
    console.log(result.rows[0])
    let user = result.rows[0];
    if(user != null) {
      var err = new Error('User ' + req.body.email + ' already exists!');
      err.status = 403;
      next(err);
    }
    else {
      pool.query(`INSERT INTO users (user_name, user_email, user_password)
      VALUES ($1, $2, $3)
      RETURNING user_id, user_name`, [name, email, hashedPassword])
      .then((user) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      console.log(user.rows[0])
      res.json({status: 'Registration Successful!', user: user.rows[0]});
    }, (err) => next(err))
      
    }
  })
  .catch((err) => next(err));
  }

});


router.post('/login',notAuth, passport.authenticate('local'), (req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.json({success: true, status: 'You are successfully logged in!'});
});

router.get("/logout",auth, (req, res) => {
  req.logout();
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.json({success: true, status: 'You are successfully logged out!'});
});

router.post('/changepassword',auth, async (req, res, next) => {
  let { password, new_password, new_password2 } = req.body;


  console.log({
    password, new_password, new_password2
  });

  if (!new_password || !new_password2 || !password) {
    var err = new Error("Please enter all fields");
      err.status = 403;
      next(err); 
  }

  else if (new_password.length < 6) {
    var err = new Error("Password must be a least 6 characters long");
      err.status = 403;
      next(err); 
  }

  else if (new_password !== new_password2) {
    var err = new Error("Passwords do not match");
      err.status = 403;
      next(err); 
  }else{
    hashedPassword = await bcrypt.hash(new_password, 10);
    console.log(hashedPassword);

    
  

  pool.query("select * from users where user_id =  $1",[req.user.user_id])
  .then(result => {
    console.log(result.rows[0])
    let user = result.rows[0];
    if(user == null) {
      var err = new Error('No such user Exist');
      err.status = 403;
      next(err);
    }
    else {
      bcrypt.compare(password, user.user_password, (err, isMatch) => {
        if (err) {
          console.log(err);
        }
        if (isMatch) {
          pool.query("update users set user_password = $1 where user_id =  $2",[hashedPassword,req.user.user_id])
          .then(result => {
            console.log(result)
          
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.json({status: 'Password Changed Please re-Login',passport: new_password});
          })
          .catch((err) => next(err));

        } else {
          //password is incorrect
          var err = new Error(" Existing Password is incorrect");
          err.status = 403;
          next(err);
        }
      });
      
      
    }
  })
  .catch((err) => next(err));
  }

});


function auth (req, res, next) {
  console.log(req.user);

  if (!req.user) {
    var err = new Error('You are not authenticated!');
    err.status = 403;
    next(err);
  }
  else {
        next();
  }
}

function notAuth (req, res, next) {
  console.log(req.user);
  if (req.user) {
    var err = new Error('You are already logged in');
    err.status = 403;
    next(err);
  }
  else {
        next();
  }
}

module.exports = router;
