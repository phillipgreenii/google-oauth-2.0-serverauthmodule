package com.idmworks.security.google;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Provides methods for saving and retrieving state.
 *
 * @author pdgreen
 */
public class StateHelper {

  private static Logger LOGGER = Logger.getLogger(GoogleOAuthServerAuthModule.class.getName());
  /*
   * Session Parameters
   */
  private static final String SESSION_PREFIX = StateHelper.class.getName() + ".";
  private static final String ORIGINAL_REQUEST_PATH = SESSION_PREFIX + "original_request_path";
  private static final String SAVED_SUBJECT = SESSION_PREFIX + "saved_subject";
  private final HttpServletRequest request;

  public StateHelper(HttpServletRequest request) {
    this.request = request;
  }

  public void saveSubject(final Subject subject) {
    if (subject == null) {
      return;
    }
    final HttpSession session = request.getSession(true);

    session.setAttribute(SAVED_SUBJECT, subject);
    LOGGER.log(Level.FINE, "Saved subject {0}", subject);
  }

  public Subject retrieveSavedSubject() {
    final HttpSession session = request.getSession(false);
    if (session != null) {
      return (Subject) session.getAttribute(SAVED_SUBJECT);
    } else {
      return null;
    }
  }

  public void saveOriginalRequestPath() {
    final HttpSession session = request.getSession(true);
    try {
      final URI orignalRequestUri = new URI(request.getRequestURI());
      session.setAttribute(ORIGINAL_REQUEST_PATH, orignalRequestUri);
      LOGGER.log(Level.FINE, "Saved original request path {0}", orignalRequestUri);
    } catch (URISyntaxException ex) {
      LOGGER.log(Level.WARNING, "Unable to save original request path", ex);
    }
  }

  public URI extractOriginalRequestPath() {
    final HttpSession session = request.getSession(false);
    if (session != null) {
      final URI originalRequestPath = (URI) session.getAttribute(ORIGINAL_REQUEST_PATH);
      session.removeAttribute(ORIGINAL_REQUEST_PATH);
      return originalRequestPath;
    } else {
      return null;
    }
  }
}
