import { PkceCodes } from '@azure/msal-common';
import { CryptoProvider, PublicClientApplication } from '@azure/msal-node';
import { BrowserWindow, shell } from 'electron';
import log from 'electron-log';
import env from './env.json';

const msalConfig = {
  auth: {
    clientId: env.AZURE_AD_CLIENT_ID,
    authority: env.AZURE_AD_AUTHORITY,
    redirectUri: env.AZURE_AD_REDIRECT_URI,
  },
};
const pca = new PublicClientApplication(msalConfig);
let pkceCodes: PkceCodes;

export async function startAzureADLoginFlow() {
  try {
    pkceCodes = await new CryptoProvider().generatePkceCodes();
    const authCodeUrlParameters = {
      scopes: env.AZURE_AD_SCOPES,
      redirectUri: env.AZURE_AD_REDIRECT_URI,
      codeChallenge: pkceCodes.challenge, // PKCE Code Challenge
      codeChallengeMethod: 'S256', // PKCE Code Challenge Method
    };
    // get url to sign user in and consent to scopes needed for application
    pca
      .getAuthCodeUrl(authCodeUrlParameters)
      .then(response => {
        shell.openExternal(response).then(() => {});
      })
      .catch(error => console.log('code fetch error', JSON.stringify(error)));
  } catch (error) {
    log.error('AzureAD, error in oauth flow start', error);
  }
}

export function handleAzureAdAuthFlow(mainWindow: BrowserWindow, url: string) {
  const urlObj = new URL(url);

  // for pkce oauth 2.0 we get the auth code
  let authCode = urlObj.hash.split('&')[0];
  if (!!authCode) {
    authCode = authCode.split('#code=')[1];
  }
  if (!authCode) {
    authCode = urlObj.searchParams.get('code');
  }

  if (!!authCode) {
    const tokenRequest = {
      code: authCode,
      codeVerifier: pkceCodes.verifier, // PKCE Code Verifier
      redirectUri: env.AZURE_AD_REDIRECT_URI,
      scopes: env.AZURE_AD_SCOPES,
    };
    pca
      .acquireTokenByCode(tokenRequest)
      .then(response => {
        mainWindow.webContents.send('auth_token', response.idToken);
        mainWindow.webContents.send('auth_access_token', response.accessToken);
      })
      .catch(error => {
        log.error('AzureAD, error in getting token from auth code', error);
      });
  }
}
