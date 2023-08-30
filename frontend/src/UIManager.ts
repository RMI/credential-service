import { AccountInfo } from "@azure/msal-browser";

// Handles all the DOM manipulations for the frontend.
export class UIManager {
  static messageDiv = document.getElementById("message");
  static signInButton = document.getElementById("signInButton");

  static getAPIKeyButton = document.getElementById("getAPIKeyButton");
  static apiKeyDiv = document.getElementById("apiKey");

  static testAPIKeyButton = document.getElementById("testAPIKeyButton");
  static testAPIKeyInput = document.getElementById("testAPIKeyInput") as HTMLInputElement
  static testAPIKey = document.getElementById("testAPIKey")

  static testAuthCookieButton = document.getElementById("testAuthCookieButton");
  static testAuthCookie = document.getElementById("testAuthCookie")

  static showWelcomeMessage(account: AccountInfo) {
    if (UIManager.messageDiv) {
      UIManager.messageDiv.innerText = `Logged in as ${account.username}`;
    }

    if (UIManager.signInButton) {
      (UIManager.signInButton.nextElementSibling as HTMLElement).style.display =
        "none";
      UIManager.signInButton.setAttribute("onclick", "App.signOut();");
      UIManager.signInButton.innerHTML = "Sign out";
    }

    if (UIManager.getAPIKeyButton) {
      UIManager.getAPIKeyButton.removeAttribute("disabled");
    }
  }

  static signOut() {
    if (UIManager.messageDiv) {
      UIManager.messageDiv.innerText = "Please sign-in to create an API key";
    }

    if (UIManager.signInButton) {
      (UIManager.signInButton.nextElementSibling as HTMLElement).style.display =
        "none";
      UIManager.signInButton.setAttribute("onclick", "App.signIn();");
      UIManager.signInButton.innerHTML = "Sign in";
    }

    if (UIManager.getAPIKeyButton) {
      UIManager.getAPIKeyButton.setAttribute("disabled", "true");
    }
  }

  static showAPIKey(id: string, key: string) {
    if (!UIManager.apiKeyDiv) {
      return;
    }
    UIManager.apiKeyDiv.innerText = `ID: ${id}\n\nAPI Key: ${key}`;
  }

  static showTestAPIKey(resp: string) {
    if (!UIManager.testAPIKey) {
      return;
    }
    UIManager.testAPIKey.innerText = resp
  }

  static showTestAuthCookie(resp: string) {
    if (!UIManager.testAuthCookie) {
      return;
    }
    UIManager.testAuthCookie.innerText = resp
  }

  static getEnteredAPIKey(): string | undefined {
    if (!UIManager.testAPIKeyInput) {
      return undefined
    }
    return UIManager.testAPIKeyInput.value || undefined 
  }
}
