import express from 'express';
import bodyParser from 'body-parser';
import { SignJWT } from 'jose';
import { generateSecret } from 'jose';
import { randomBytes } from 'crypto';

const app = express();
const port = 8080;

app.use(bodyParser.urlencoded({ extended: true }));

const validClientId = 'upfirst';
const validRedirectUri = 'http://localhost:8081/process';

interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  expiresAt: Date;
}

interface RefreshToken {
  clientId: string;
  expiresAt: Date;
}

const authorizationCodes = new Map<string, AuthorizationCode>();
const refreshTokens = new Map<string, RefreshToken>();
let secret: Uint8Array;

async function initializeSecret() {
  secret = await generateSecret('HS256') as Uint8Array;
}

app.get('/api/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, state } = req.query;

  // Validate parameters
  if (response_type !== 'code') {
    return redirectWithError(res, redirect_uri, 'invalid_request', 'response_type must be code');
  }

  if (client_id !== validClientId) {
    return redirectWithError(res, redirect_uri, 'invalid_client', 'Invalid client ID');
  }

  if (redirect_uri !== validRedirectUri) {
    return redirectWithError(res, redirect_uri, 'invalid_request', 'Invalid redirect URI');
  }

  // Generate authorization code
  const code = randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  authorizationCodes.set(code, {
    clientId: client_id as string,
    redirectUri: redirect_uri as string,
    expiresAt,
  });

  // Build redirect URL
  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state as string);

  res.redirect(302, redirectUrl.toString());
});

app.post('/api/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, redirect_uri, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    // Handle authorization code flow
    const authCode = authorizationCodes.get(code);
    if (!authCode || authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    if (authCode.expiresAt < new Date()) {
      authorizationCodes.delete(code);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
    }

    // Generate tokens
    const accessToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(secret);

    const refreshToken = randomBytes(32).toString('hex');
    refreshTokens.set(refreshToken, {
      clientId: client_id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    });

    authorizationCodes.delete(code);
    return res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: refreshToken
    });
  }

  if (grant_type === 'refresh_token') {
    // Handle refresh token flow
    const refreshTokenData = refreshTokens.get(refresh_token);
    if (!refreshTokenData || refreshTokenData.clientId !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    if (refreshTokenData.expiresAt < new Date()) {
      refreshTokens.delete(refresh_token);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token expired' });
    }

    // Generate new access token
    const newAccessToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(secret);

    // Generate new refresh token (optional rotation)
    const newRefreshToken = randomBytes(32).toString('hex');
    refreshTokens.set(newRefreshToken, {
      clientId: client_id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    // Delete old refresh token
    refreshTokens.delete(refresh_token);

    return res.json({
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: newRefreshToken
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

function redirectWithError(res: express.Response, uri: any, error: string, description: string) {
  const url = new URL(uri || validRedirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  return res.redirect(url.toString());
}

async function startServer() {
  await initializeSecret();
  app.listen(port, () => {
    console.log(`OAuth server running on http://localhost:${port}`);
  });
}

startServer();