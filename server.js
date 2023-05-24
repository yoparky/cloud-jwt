const express = require('express');
const app = express();

const {Datastore} = require('@google-cloud/datastore');

const bodyParser = require('body-parser');
const request = require('request');

const datastore = new Datastore({
    projectId: 'a7-jwt',
  });

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const BOAT = "Boat";

const eh = require('express-handlebars');
app.engine('handlebars', eh.engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

const router = express.Router();
const login = express.Router();

const CLIENT_ID = 'Flobmhc4jGDbDWLJIJ69eVBI8KBibOMg';
const CLIENT_SECRET = 'vItKIt4yrqz056QeeTSixSdmqw4a652nEl3_haDZqVMJfQ6ZfmQ2mb4aZJVwVlpJ';
const DOMAIN = 'a7-jwt.us.auth0.com';

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256'],
    // If its false, continue to the next middleware if the request does not contain a token instead of failing
    // if jwt is invalid or missing, req.user will be undefined
    credentialsRequired: false
  });

const { auth } = require('express-openid-connect');

const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: 'http://localhost:8080',
  clientID: 'Flobmhc4jGDbDWLJIJ69eVBI8KBibOMg',
  issuerBaseURL: 'https://a7-jwt.us.auth0.com',
  secret: 'vItKIt4yrqz056QeeTSixSdmqw4a652nEl3_haDZqVMJfQ6ZfmQ2mb4aZJVwVlpJ'
};

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

// routes for login, logout, view id_token
const { requiresAuth } = require('express-openid-connect');

app.get('/profile', requiresAuth(), (req, res) => {
    res.render('token-login');
});

app.post('/submit', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    var options = { method: 'POST',
            url: `https://${DOMAIN}/oauth/token`,
            headers: { 'content-type': 'application/json' },
            body:
             { grant_type: 'password',
               username: username,
               password: password,
               client_id: CLIENT_ID,
               client_secret: CLIENT_SECRET },
            json: true };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).send(error);
        } else {
            const info = {};
            info.access_token = body.access_token;
            info.id_token = body.id_token;
            res.render('info', info);
        }
    });
  });

app.get('/', (req, res) => {
    req.oidc.isAuthenticated() ? res.render('home') : res.redirect('/login');

});

/* ------------- Begin boat Model Functions ------------- */
function post_boat(name, type, length, public, owner){
    var key = datastore.key(BOAT);
	const new_boat = {"name": name, "type": type, "length": length, "public": public, "owner":owner};
    
	return datastore.save({"key":key, "data":new_boat}).then(() => {return key});
}

async function get_owner_boat(owner) {
    const query = datastore
    .createQuery(BOAT)
    .filter('owner', '=', owner)
    .filter('public', '=', true);

    const [boats] = await datastore.runQuery(query);
    return boats
}

async function get_boats(query) {
    const [boats] = await datastore.runQuery(query);
    return boats
}

function get_boat(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    return datastore.get(key).then(entity => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

function delete_boat(id) {
    const key = datastore.key([BOAT, parseInt(id,10)]);
    return datastore.delete(key);
}

/* ------------- End Model Functions ------------- */

/* ------------- Begin Controller Functions ------------- */
router.post('/boats', checkJwt, function(req, res){
    if (!req.user) {
        return res.status(401).json({"Error": 'Missing or invalid jwt'});
    }
    var name = req.body.name;
    var type = req.body.type;
    var length = req.body.length;
    var public = req.body.public;
    post_boat(name, type, length, public, req.user.sub)
    .then( key => {res.status(201).json(
        {
            "id": key.id,
            "name": name,
            "type": type,
            "length":length,
            "public": public,
            "owner": req.user.sub
        })
    });
});

router.get('/owners/:owner/boats', function(req, res){
    const boats = get_owner_boat(req.params.owner)
    .then ((boats) => {res.status(200).json(boats);});
});


router.get('/boats', checkJwt, async function(req, res){
    // owner is null if there is no req.user
    const owner = req.user ? req.user.sub : null;
    const q = owner ? datastore.createQuery(BOAT).filter('owner', '=', owner)
                    : datastore.createQuery(BOAT).filter('public', '=', true);
    get_boats(q)
    .then ((boats) => {res.status(200).json(boats);});
});

router.delete('/boats/:boat_id', checkJwt, async function(req, res){
    if (!req.user) {
        return res.status(401).json({"Error": 'Missing or invalid jwt'});
    }

    const id = req.params.boat_id;
    const owner = req.user.sub;

    get_boat(id)
    .then(async boat => {
        if (boat[0] === undefined || boat[0] === null) {
            res.status(403).json({"Error": "No boat with this boat_id exists"});
        } else if (boat[0].owner !== owner) {
            res.status(403).json({"Error": "Boat is owned by different owner"});
        } else {
            await delete_boat(id)
            .then (res.status(204).end());
        }
    })
});

app.get('/', function(req, res) {
    res.render('home');
    req.oidc.isAuthenticated() ? res.render('home') : res.render('login');
});

login.post('/', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    var options = { method: 'POST',
            url: `https://${DOMAIN}/oauth/token`,
            headers: { 'content-type': 'application/json' },
            body:
             { grant_type: 'password',
               username: username,
               password: password,
               client_id: CLIENT_ID,
               client_secret: CLIENT_SECRET },
            json: true };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).send(error);
        } else {
            res.send(body);
        }
    });

});

/* ------------- End Controller Functions ------------- */

app.use('/', router);
app.use('/login', login);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});