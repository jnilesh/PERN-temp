var express = require('express');
var router = express.Router();
const pool = require("../db");
const bcrypt = require("bcrypt");

/* GET users listing. */
router.get('/', function(req, res, next) {
  pool.query("select * from users")
  .then(result => {
    console.log(result.rows)
  })
  res.send('respond with a resource');
});

router.post('/signup', async (req, res, next) => {
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
      // let sql = INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3)";
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

  // User.findOne({username: req.body.username})
  // .then((user) => {
  //   if(user != null) {
  //     var err = new Error('User ' + req.body.username + ' already exists!');
  //     err.status = 403;
  //     next(err);
  //   }
  //   else {
  //     return User.create({
  //       username: req.body.username,
  //       password: req.body.password});
  //   }
  // })
  // .then((user) => {
  //   res.statusCode = 200;
  //   res.setHeader('Content-Type', 'application/json');
  //   console.log(user)
  //   res.json({status: 'Registration Successful!', user: user});
  // }, (err) => next(err))
  .catch((err) => next(err));

  }


    
});

module.exports = router;
