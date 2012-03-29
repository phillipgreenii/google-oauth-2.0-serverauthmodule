package com.idmworks.security.google;

import com.idmworks.security.google.GoogleUserInfoCallBack;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * Login module that will add the domain as a principal.
 *
 * @author pdgreen
 */
public class DomainLoginModule implements LoginModule {

  private static Logger LOGGER = Logger.getLogger(DomainLoginModule.class.getName());
  private CallbackHandler callbackHandler;
  private Subject subject;
  private Domain domain;
  private boolean success = false;

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
    LOGGER.log(Level.FINER, "initialize()");
    this.subject = subject;
    this.callbackHandler = callbackHandler;
  }

  static LoginException wrapExceptionAsLoginException(final String message, final Exception exception) {
    LOGGER.log(Level.FINE, "LoginException wrapping: " + message, exception);
    final LoginException le = new LoginException(message);
    le.initCause(exception);
    return le;
  }

  static IllegalStateException wrapExceptionAsIllegalStateException(final String message, final Exception exception) {
    LOGGER.log(Level.FINE, "IllegalStateException wrapping: " + message, exception);
    return new IllegalStateException(message, exception);
  }

  @Override
  public boolean login() throws LoginException {
    LOGGER.log(Level.FINER, "login()");
    String email;
    try {
      final GoogleUserInfoCallBack guic = new GoogleUserInfoCallBack();
      callbackHandler.handle(new Callback[]{guic});
      email = guic.getGoogleUserInfo().getEmail();
    } catch (IOException ex) {
      success = false;
      throw wrapExceptionAsIllegalStateException("Unable to get Email", ex);
    } catch (UnsupportedCallbackException ex) {
      success = false;
      throw wrapExceptionAsIllegalStateException("Unable to get Email", ex);
    }

    domain = parseDomainFrom(email);

    success = domain != null;

    if (!success) {
      throw new LoginException("Unable to determine domain from " + email);
    }

    success = true;
    return true;
  }

  static Domain parseDomainFrom(final String email) {
    if (email == null) {
      return null;
    }
    final String[] parts = email.toLowerCase().split("@");
    if (parts.length == 2) {
      return new Domain(parts[1]);
    } else {
      LOGGER.log(Level.WARNING, "Unable to parse domain from {0}", email);
      return null;
    }
  }

  @Override
  public boolean commit() throws LoginException {
    LOGGER.log(Level.FINER, "commit()");
    subject.getPrincipals().add(domain);
    cleanup();
    return true;
  }

  @Override
  public boolean abort() throws LoginException {
    LOGGER.log(Level.FINER, "abort()");
    cleanup();
    return true;
  }

  @Override
  public boolean logout() throws LoginException {
    LOGGER.log(Level.FINER, "logout()");
    cleanup();
    subject.getPrincipals().removeAll(subject.getPrincipals(Domain.class));
    return true;
  }

  void cleanup() {
    success = false;
    domain = null;
  }

  static class Domain implements Principal {

    private final String name;

    public Domain(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      return getName();
    }
  }
}
