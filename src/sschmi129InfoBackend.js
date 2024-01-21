require('dotenv').config();


const express = require('express');
const passport = require('passport');
const cors = require('cors');


const session = require('express-session');
const crypto = require('crypto');

const app = express();

const rateLimit = require("express-rate-limit");


const servicename = process.env.SERVICENAME;
const corsOrigin = process.env.CORSORIGIN;
const dataBaseUser = process.env.DATABASEUSER;
const dataBaseName = process.env.DATABASENAME;
const dataBasePassword = process.env.DATABASEPASSWORD;
const sessionName = process.env.SESSIONNAME;
const sessionSecret = process.env.SESSIONSECRET;

if(!servicename | !corsOrigin | !dataBaseUser | !dataBaseName | !dataBasePassword | !sessionName | !sessionSecret){
  console.log("exit");
  process.exit();
}


const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
	standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
	// store: ... , // Use an external store for consistency across multiple server instances.
});

app.use(limiter);


//database
const Pool = require('pg').Pool;
const pgSession = require('connect-pg-simple')(session);

app.use(cors({
  origin: [corsOrigin, 'https://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


function genPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

  return {
    salt: salt,
    hash: genHash
  }
}

function validPassword(password, hash, salt) {
  const hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === hashVerify;
}

//passport
const LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function verify(username, password, done) {
    pgPool.query(`SELECT * FROM users WHERE username='${username}';`,
      function (error, results) {
        if (error) {
          return done(error);
        }
        if (!results || results.rows.length === 0) {
          return done(null, false);
        }
        // is sql giving user object??
        const isValid = validPassword(password, results.rows[0].hash, results.rows[0].salt);
        if (isValid) {
          const user = { id: results.rows[0].id, username: results.rows[0].username, hash: results.rows[0].hash, salt: results.rows[0].salt };
          return done(null, user);
        } else {
          return done(null, false);
        }
      });
  }
));

const pgPool = new Pool({
  user: dataBaseUser,
  host: servicename,
  database: dataBaseName,
  password: dataBasePassword,
  port: 5432,
});

const pgPoolCookie_user = new Pool({
  user: dataBaseUser,
  host: servicename,
  database: 'cookie_user',
  password: dataBasePassword,
  port: 5432
});

app.set('trust proxy', 1);

app.use(session({
  store: new pgSession({
    pool: pgPoolCookie_user,
    tableName: 'session'
  }),
  name: sessionName,
  secret: sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: {
    proxy: true,
    maxAge: 3600000, // maxAge: 1000 * 60 * 60 * 24 * 7
    sameSite: 'none',
    secure: true, // HTTPS
    httpOnly: true,
  },
}));


app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser((user, done) => {
  return done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  pgPool.query(`SELECT * FROM users WHERE id=${userId};`, (error, results) => {
    if (error) {
      return done(error);
    }

    return done(null, results.rows[0]);
  });
});

function isAuthForGettingInfo(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    return res.sendStatus(401);
  }
}

app.post('/login',
  passport.authenticate('local'),
  function (req, res) {
    return res.sendStatus(200);
  }
);


app.post('/register', async (req, res, next) => {
  //username and password transmitted???
  if (!req.body.username || !req.body.password) {
    return res.status(400).send({
      error: "Username or/and password missing."
    });
  }


  //username is taken
  try {
    const usernameCount = await pgPool.query(`SELECT COUNT(*) FROM users WHERE username='${req.body.username}';`);
    if (usernameCount.rows[0].count >= 1) {
      return res.status(400).send({
        error: "Username is already taken."
      }
      );
    };

  } catch (err) {
    return res.sendStatus(500);
  }



  //password validator
  /*
  minimum length requirement (8)
  max length requirement (32)
  at least one upper case letter
  one lower case letter
  one number
  one special character
  */
  const passwordValidatorRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/;
  if (!passwordValidatorRegex.test(req.body.password)) {
    return res.status(400).send({
      error: "Password doesn't fulfill the requirements."
    }
    );
  }

  //create user
  const saltHash = genPassword(req.body.password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;
  try {
    await pgPool.query(`INSERT INTO users VALUES (default, '${req.body.username}', '${hash}', '${salt}');`);
  } catch (err) {
    return res.sendStatus(500);
  }

  return res.sendStatus(201);
});

app.post('/message', isAuthForGettingInfo, (req, res, next) => {
  if (!req.body.message || !req.user.username) {
    return res.sendStatus(500);
  }

  pgPool.query(`INSERT INTO messages (userId, message)
  SELECT  users.id, '${req.body.message}'
  FROM    users
  WHERE   users.username = '${req.user.username}';`, (error, results) => {
    if (error) {
      return res.sendStatus(500);
    }
  });
  res.sendStatus(201);
});

app.get('/message', isAuthForGettingInfo, (req, res, next) => {

  pgPool.query(`SELECT id, message FROM messages WHERE userId IN (SELECT id FROM users WHERE username='${req.user.username}');`, (error, results) => {
    if (error) {
      console.error(error);
      return res.sendStatus(500);
    }
    return res.send(results.rows);
  });
});

app.delete('/message', isAuthForGettingInfo, (req, res, next) => {

  pgPool.query(`DELETE FROM messages WHERE id=${req.body.id} AND userId IN (SELECT id FROM users WHERE username='${req.user.username}');`, (error, results) => {
    if (error) {
      console.error(error);
      return res.sendStatus(500);
    }
  });

  return res.sendStatus(200);
});



app.get('/user', isAuthForGettingInfo, async (req, res, next) => {
  pgPool.query(`SELECT username FROM users WHERE username='${req.user.username}';`, (error, results) => {
    if (error) {
      return res.sendStatus(500);
    }
    return res.json(results.rows);
  });
});

app.get('/modules', isAuthForGettingInfo, (req, res, next) => {
  pgPool.query("SELECT * FROM modules;", (error, results) => {
    if (error) {
      return res.sendStatus(500);
    }
    return res.json(results.rows);
  });
});

app.get('/leistungsuebersicht', isAuthForGettingInfo, (req, res, next) => {
  return res.sendFile(__dirname + '/leistungsuebersicht.pdf')
});

app.post('/logout', isAuthForGettingInfo, function (req, res, next) {
  req.logout(
    function (err) {
      if (err) {
        return next(err);
      
      }
      return res.sendStatus(302);
    });
});

// app.get('/', (req, res, next) => {
//   return res.sendStatus(200);
// });

const cron = require('node-cron');
const { exit } = require('process');

cron.schedule('0 1 * * *', () => {
  pgPool.query(`DELETE FROM users WHERE NOT username=${dataBaseUser};`, (error, results) => {
    if (error) {
      return;
    }
  });
  
});

app.listen(3000);
