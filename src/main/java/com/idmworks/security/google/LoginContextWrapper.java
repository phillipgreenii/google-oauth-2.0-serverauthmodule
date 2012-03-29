package com.idmworks.security.google;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Wrapper for {@link LoginContext} which properly handles null.
 *
 * @author pdgreen
 */
public class LoginContextWrapper {

  private final LoginContext wrapped;

  public LoginContextWrapper(LoginContext wrapped) {
    this.wrapped = wrapped;
  }

  public void login() throws LoginException {
    if (wrapped != null) {
      wrapped.login();
    }
  }

  public void logout() throws LoginException {
    if (wrapped != null) {
      wrapped.logout();
    }
  }

  public Subject getSubject() {
    if (wrapped != null) {
      return wrapped.getSubject();
    } else {
      return new Subject();
    }
  }
}
