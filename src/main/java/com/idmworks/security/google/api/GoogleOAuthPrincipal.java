package com.idmworks.security.google.api;

import java.security.Principal;

/**
 * Principal for user authenticated with Google OAuth.
 *
 * @author pdgreen
 */
public class GoogleOAuthPrincipal implements Principal {

  private final GoogleUserInfo googleUserInfo;

  public GoogleOAuthPrincipal(GoogleUserInfo googleUserInfo) {
    this.googleUserInfo = googleUserInfo;
  }

  @Override
  public String getName() {
    return googleUserInfo.getEmail();
  }

  public GoogleUserInfo getGoogleUserInfo() {
    return googleUserInfo;
  }

  @Override
  public String toString() {
    return new StringBuilder().append("{").append(GoogleOAuthPrincipal.class.getSimpleName()).append(":").append(getName()).append("}").toString();
  }
}
