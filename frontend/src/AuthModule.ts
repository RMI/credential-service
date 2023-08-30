import {
  PublicClientApplication,
  AuthenticationResult,
  Configuration,
  LogLevel,
  AccountInfo,
  RedirectRequest,
  PopupRequest,
  EndSessionRequest,
  CacheLookupPolicy,
} from "@azure/msal-browser";
import b2cPolicy from "../auth.json";
import { UIManager } from "./UIManager";

/**
 * Configuration class for @azure/msal-browser:
 * https://azuread.github.io/microsoft-authentication-library-for-js/ref/msal-browser/modules/_src_config_configuration_.html
 */

const MSAL_CONFIG: Configuration = {
  auth: b2cPolicy,
  cache: {
    cacheLocation: "localStorage",
    storeAuthStateInCookie: true,
  },
  system: {
    loggerOptions: {
      loggerCallback: (
        level: LogLevel,
        message: string,
        containsPii: boolean,
      ) => {
        if (containsPii) {
          return;
        }
        switch (level) {
          case LogLevel.Error:
            console.error(message);
            return;
          case LogLevel.Info:
            console.info(message);
            return;
          case LogLevel.Verbose:
            console.debug(message);
            return;
          case LogLevel.Warning:
            console.warn(message);
            return;
          default:
            return;
        }
      },
      logLevel: LogLevel.Verbose,
    },
  },
};

/**
 * AuthModule for application - handles authentication in app.
 */
export class AuthModule {
  private msalClient: PublicClientApplication; // https://azuread.github.io/microsoft-authentication-library-for-js/ref/msal-browser/classes/_src_app_publicclientapplication_.publicclientapplication.html
  private account: AccountInfo | null; // https://azuread.github.io/microsoft-authentication-library-for-js/ref/msal-common/modules/_src_account_accountinfo_.html
  private loginRedirectRequest: RedirectRequest; // https://azuread.github.io/microsoft-authentication-library-for-js/ref/msal-browser/modules/_src_request_redirectrequest_.html
  private loginRequest: PopupRequest; // https://azuread.github.io/microsoft-authentication-library-for-js/ref/msal-browser/modules/_src_request_popuprequest_.html

  constructor() {
    this.msalClient = new PublicClientApplication(MSAL_CONFIG);
    this.account = null;

    this.loginRequest = {
      scopes: [],
    };

    this.loginRedirectRequest = {
      ...this.loginRequest,
      redirectStartPage: window.location.href,
    };
  }

  async getIDToken(): Promise<string | undefined> {
    if (!this.account) {
      return undefined;
    }
    const result = await this.msalClient.acquireTokenSilent({
      scopes: [],
      cacheLookupPolicy: CacheLookupPolicy.Default,
      account: this.account,
    });
    return result.idToken;
  }

  /**
   * Calls getAllAccounts and determines the correct account to sign into, currently defaults to first account found in cache.
   * TODO: Add account chooser code
   *
   * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-common/docs/Accounts.md
   */
  private getAccount(): AccountInfo | null {
    // need to call getAccount here?
    const currentAccounts = this.msalClient.getAllAccounts();
    if (currentAccounts === null) {
      console.log("No accounts detected");
      return null;
    }

    if (currentAccounts.length > 1) {
      // Add choose account code here
      console.log(
        "Multiple accounts detected, need to add choose account code.",
      );
      return currentAccounts[0];
    } else if (currentAccounts.length === 1) {
      return currentAccounts[0];
    }

    return null;
  }

  /**
   * Checks whether we are in the middle of a redirect and handles state accordingly. Only required for redirect flows.
   *
   * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-browser/docs/initialization.md#redirect-apis
   */
  async loadAuthModule(): Promise<void> {
    await this.msalClient.initialize();
    const resp = await this.msalClient.handleRedirectPromise();
    this.handleResponse(resp);
  }

  /**
   * Handles the response from a popup or redirect. If response is null, will check if we have any accounts and attempt to sign in.
   * @param response
   */
  handleResponse(response: AuthenticationResult | null) {
    this.account = response?.account || this.getAccount();

    if (this.account) {
      UIManager.showWelcomeMessage(this.account);
    }
  }

  /**
   * Calls loginPopup or loginRedirect based on given signInType.
   * @param signInType
   */
  async login(signInType: "loginPopup" | "loginRedirect"): Promise<void> {
    switch (signInType) {
      case "loginPopup":
        const resp = await this.msalClient.loginPopup(this.loginRequest)
        this.handleResponse(resp);
        break;
      case "loginRedirect":
        await this.msalClient.loginRedirect(this.loginRedirectRequest);
        break;
    }
  }

  /**
   * Logs out of current account.
   */
  async logout(): Promise<void> {
    let account: AccountInfo | undefined;
    if (this.account) {
      account = this.account;
    }
    const logOutRequest: EndSessionRequest = {
      account,
    };

    await this.msalClient.logoutRedirect(logOutRequest);
  }
}
