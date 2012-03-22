package com.idmworks.security;

import java.security.Principal;

/**
 * Principal for user authenticated with Google OAuth
 *
 * @author pdgreen
 */
public class GoogleOAuthPrincipal implements Principal {

  private final String email;

  public GoogleOAuthPrincipal(String email) {
    this.email = email;
  }

  @Override
  public String getName() {
    return email;
  }

  public String getEmail() {
    return email;
  }
}
