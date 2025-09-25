const express = require('express');
const path = require('path');
const { Provider } = require('oidc-provider');

const app = express();
app.use(express.urlencoded({ extended: true })); // handle form POST

// EJS for custom login page
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Dummy users with extra profile info
const users = [
  {
    id: '1',
    username: 'alice',
    password: 'password123',
    email: 'alice@example.com',
    full_name: 'Alice Smith',
    phone_number: '+911234567890',
    permissions: ['read', 'write']
  },
  {
    id: '2',
    username: 'bob',
    password: 'mypassword',
    email: 'bob@example.com',
    full_name: 'Bob Johnson',
    phone_number: '+919876543210',
    permissions: ['read']
  }
];

// Simple in-memory user lookup
function findUser(username, password) {
  return users.find(u => u.username === username && u.password === password);
}

// OIDC Provider configuration
const configuration = {
  clients: [{
    client_id: "oidcCLIENT",
    client_secret: "Some_super_secret",
    grant_types: ["authorization_code"],
    redirect_uris: ["http://localhost:8080/auth/login/callback"],
    response_types: ["code"],
    scope: "openid email profile permissions", // <-- define allowed scopes for this client
  }],
  pkce: { required: () => false },

  // Scope -> claims mapping
  claims: {
    openid: ['sub'],
    email: ['email'],
    profile: ['username', 'full_name', 'phone_number'],
    permissions: ['permissions']
  },
  findAccount: async (ctx, id) => {
    const user = users.find(u => u.id === id);
    if (!user) return undefined;

    return {
      accountId: id,
      async claims(use, scope) {
        const claims = { sub: user.id };

        if (scope.includes('email')) {
          claims.email = user.email;
        }
        if (scope.includes('profile')) {
          claims.username = user.username;
          claims.full_name = user.full_name;
          claims.phone_number = user.phone_number;
        }
        if (scope.includes('permissions')) {
          claims.permissions = user.permissions;
        }

        return claims;
      }}}




};

// Create Provider instance
const oidc = new Provider('http://localhost:3000', configuration);
oidc.proxy = true;

// Allow interaction routes
oidc.use(async (ctx, next) => {
  if (ctx.path.startsWith('/interaction')) return next();
  return next();
});

// Interaction route: show login form
app.get('/oidc/interaction/:uid', async (req, res) => {
  const { uid, prompt, params, session } = await oidc.interactionDetails(req, res);

  if (prompt.name === 'login') {
    res.render('login', { uid, params, error: null });
  } else if (prompt.name === 'consent') {
    // Create or reuse a grant
    let grant;
    if (session.grantId) grant = await oidc.Grant.find(session.grantId);
    if (!grant) {
      grant = new oidc.Grant({ accountId: session.accountId, clientId: params.client_id });
    }

    // Add scopes/claims requested by client
    if (params.scope) grant.addOIDCScope(params.scope);

    // Add all claims for these scopes (you can customize)
    grant.addOIDCClaims(['sub', 'email', 'username', 'full_name', 'phone_number', 'permissions']);

    const grantId = await grant.save();
    await oidc.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
  } else {
    await oidc.interactionFinished(req, res, { consent: {} }, { mergeWithLastSubmission: true });
  }
});

// Handle login POST
app.post('/oidc/interaction/:uid/login', async (req, res, next) => {
  try {
    const { uid } = req.params;
    const { username, password } = req.body;

    const user = findUser(username, password);
    if (!user) {
      return res.render('login', { uid, params: {}, error: 'Invalid username or password' });
    }

    const result = { login: { accountId: user.id } };
    await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});

// Attach provider
app.use('/oidc', oidc.callback());

// Start server
app.listen(3000, () => {
  console.log('OIDC Provider listening on http://localhost:3000');
});