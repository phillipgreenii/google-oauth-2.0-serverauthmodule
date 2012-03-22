package com.idmworks.security;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SAM ({@link ServerAuthModule}) for Google OAuth.
 *
 * @author pdgreen
 */
public class GoogleOAuthServerAuthModule implements ServerAuthModule {

  public static final String DEFAULT_ENDPOINT = "https://accounts.google.com/o/oauth2/auth";
  public static final String DEFAULT_OAUTH_AUTHETICATION_REDIRECT = "/j_oauth_check";
  private static final String ENDPOINT_PROPERTY_NAME = "oauth.endpoint";
  private static final String CLIENTID_PROPERTY_NAME = "oauth.clientid";
  private static final String REDIRECTURI_PROPERTY_NAME = "oauth.redirect_uri";
  private static Logger LOGGER = Logger.getLogger(GoogleOAuthServerAuthModule.class.getName());
  protected static final Class[] SUPPORTED_MESSAGE_TYPES = new Class[]{
    javax.servlet.http.HttpServletRequest.class,
    javax.servlet.http.HttpServletResponse.class};
  private MessagePolicy requestPolicy;
  private MessagePolicy responsePolicy;
  private CallbackHandler handler;
  private Map<String, String> options;
  private boolean mandatory;
  //properties
  private String endpoint;
  private String clientid;
  private String oauthAuthenticationRedirect;

  String retrieveProperty(final Map<String, String> properties, final String name, final String defaultValue) {
    if (properties.containsKey(name)) {
      return properties.get(name);
    } else {
      return defaultValue;
    }
  }

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
    this.requestPolicy = requestPolicy;
    this.responsePolicy = responsePolicy;
    this.handler = handler;
    this.options = options;
    this.mandatory = requestPolicy.isMandatory();
    //properties
    this.endpoint = retrieveProperty(options, ENDPOINT_PROPERTY_NAME, DEFAULT_ENDPOINT);
    this.clientid = retrieveProperty(options, CLIENTID_PROPERTY_NAME, null);
    this.oauthAuthenticationRedirect = retrieveProperty(options, REDIRECTURI_PROPERTY_NAME, DEFAULT_OAUTH_AUTHETICATION_REDIRECT);
    if (this.clientid == null) {
      throw new AuthException("Required field \"" + CLIENTID_PROPERTY_NAME + "\" not specified!");
    }
  }

  @Override
  public Class[] getSupportedMessageTypes() {
    return SUPPORTED_MESSAGE_TYPES;
  }

  @Override
  public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

    final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
    final HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

    if (isOauthResponse(request)) {
      setCallerPrincipal(clientSubject, "test-user@idmworks.com");
      return AuthStatus.SUCCESS;
    } else {
      final String redirectUri = buildRedirectUri(request);
      final String oauthUrl = buildOauthUrl(redirectUri);
      try {
        LOGGER.log(Level.FINE, "redirecting to {} for OAuth", new Object[]{oauthUrl});
        response.sendRedirect(oauthUrl);
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + oauthUrl, ex);
      }
      return AuthStatus.SEND_CONTINUE;
    }
  }

  boolean isOauthResponse(final HttpServletRequest request) {
    return request.getRequestURI().contains(oauthAuthenticationRedirect);//FIXME needs better check
  }

  String buildRedirectUri(final HttpServletRequest request) {
    final String serverScheme = request.getScheme();
    final String serverUserInfo = null;
    final String serverHost = request.getServerName();
    final int serverPort = request.getServerPort();
    final String path = request.getContextPath() + oauthAuthenticationRedirect;
    final String query = null;
    final String serverFragment = null;
    try {
      return new URI(serverScheme, serverUserInfo, serverHost, serverPort, path, query, serverFragment).toString();
    } catch (URISyntaxException ex) {
      throw new IllegalStateException("Unable to build redirectUri", ex);
    }
  }

  String buildOauthUrl(final String redirectUri) {


    final StringBuilder sb = new StringBuilder(endpoint);
    sb.append("?");
    sb.append("scope").append("=").append("https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile");
    sb.append("&");
    sb.append("redirect_uri").append("=").append(redirectUri);
    sb.append("&");
    sb.append("response_type").append("=").append("code");
    sb.append("&");
    sb.append("client_id").append("=").append(clientid);
    return sb.toString();
  }

  boolean setCallerPrincipal(Subject clientSubject, String email) {
    final CallerPrincipalCallback principalCallback = new CallerPrincipalCallback(
            clientSubject, new GoogleOAuthPrincipal(email));
    final GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, new String[]{"user"});
    try {
      handler.handle(new Callback[]{principalCallback, groupCallback});
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "unable to set caller and groups", e);
      return false;
    }

    return true;
  }

  @Override
  public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
    //TODO what needs to happen here?
    return AuthStatus.SEND_SUCCESS;
  }

  @Override
  public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    //TODO do i need to check messageInfo so that i only remove the specific GoogleOAuthPrincipal instance?
    subject.getPrincipals().removeAll(subject.getPrincipals(GoogleOAuthPrincipal.class));
  }
}
