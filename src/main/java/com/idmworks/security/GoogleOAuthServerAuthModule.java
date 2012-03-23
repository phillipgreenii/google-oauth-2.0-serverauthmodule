package com.idmworks.security;

import com.idmworks.security.google.GoogleApiUtils;
import com.idmworks.security.google.api.GoogleOAuthPrincipal;
import com.idmworks.security.google.api.GoogleUserInfo;
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

  public static final String DEFAULT_OAUTH_CALLBACK_PATH = "/j_oauth_callback";
  private static final String ENDPOINT_PROPERTY_NAME = "oauth.endpoint";
  private static final String CLIENTID_PROPERTY_NAME = "oauth.clientid";
  private static final String CLIENTSECRET_PROPERTY_NAME = "oauth.clientsecret";
  private static final String CALLBACK_URI_PROPERTY_NAME = "oauth.callback_uri";
  private static Logger LOGGER = Logger.getLogger(GoogleOAuthServerAuthModule.class.getName());
  protected static final Class[] SUPPORTED_MESSAGE_TYPES = new Class[]{
    javax.servlet.http.HttpServletRequest.class,
    javax.servlet.http.HttpServletResponse.class};
  private CallbackHandler handler;
  //properties
  private String clientid;
  private String clientSecret;
  private String endpoint;
  private String oauthAuthenticationCallbackUri;

  String retrieveOptionalProperty(final Map<String, String> properties, final String name, final String defaultValue) {
    if (properties.containsKey(name)) {
      return properties.get(name);
    } else {
      return defaultValue;
    }
  }

  String retrieveRequiredProperty(final Map<String, String> properties, final String name) throws AuthException {
    if (properties.containsKey(name)) {
      return properties.get(name);
    } else {
      final String message = String.format("Required field '%s' not specified!", name);
      throw new AuthException(message);
    }
  }

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
    this.handler = handler;
    //properties
    this.clientid = retrieveRequiredProperty(options, CLIENTID_PROPERTY_NAME);
    this.clientSecret = retrieveRequiredProperty(options, CLIENTSECRET_PROPERTY_NAME);
    this.endpoint = retrieveOptionalProperty(options, ENDPOINT_PROPERTY_NAME, GoogleApiUtils.TOKEN_API_URI_DEFAULT_ENDPOINT);
    this.oauthAuthenticationCallbackUri = retrieveOptionalProperty(options, CALLBACK_URI_PROPERTY_NAME, DEFAULT_OAUTH_CALLBACK_PATH);
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
      final String authorizationCode = request.getParameter(GoogleApiUtils.TOKEN_API_CODE_PARAMETER);
      final String error = request.getParameter(GoogleApiUtils.TOKEN_API_ERROR_PARAMETER);
      if (error != null && !error.isEmpty()) {
        LOGGER.log(Level.WARNING, "Error authorizing: {0}", new Object[]{error});
        return AuthStatus.FAILURE;
      } else {
        final String redirectUri = buildRedirectUri(request);
        final AccessTokenInfo accessTokenInfo = GoogleApiUtils.lookupAccessTokeInfo(redirectUri, authorizationCode, clientid, clientSecret);
        LOGGER.log(Level.FINE, "Access Token: {0}", new Object[]{accessTokenInfo});

        final GoogleUserInfo googleUserInfo = GoogleApiUtils.retrieveGoogleUserInfo(accessTokenInfo);

        setCallerPrincipal(clientSubject, googleUserInfo);
        return AuthStatus.SUCCESS;
      }
    } else if (isMandatory(messageInfo)) {
      return AuthStatus.SUCCESS;
    } else {
      final String redirectUri = buildRedirectUri(request);
      final URI oauthUri = GoogleApiUtils.buildOauthUri(redirectUri, endpoint, clientid);
      try {
        LOGGER.log(Level.FINE, "redirecting to {0} for OAuth", new Object[]{oauthUri});
        response.sendRedirect(oauthUri.toString());
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + oauthUri, ex);
      }
      return AuthStatus.SEND_CONTINUE;
    }
  }

  boolean isOauthResponse(final HttpServletRequest request) {
    return request.getRequestURI().contains(oauthAuthenticationCallbackUri);//FIXME needs better check
  }

  String buildRedirectUri(final HttpServletRequest request) {
    final String serverScheme = request.getScheme();
    final String serverUserInfo = null;
    final String serverHost = request.getServerName();
    final int serverPort = request.getServerPort();
    final String path = request.getContextPath() + oauthAuthenticationCallbackUri;
    final String query = null;
    final String serverFragment = null;
    try {
      return new URI(serverScheme, serverUserInfo, serverHost, serverPort, path, query, serverFragment).toString();
    } catch (URISyntaxException ex) {
      throw new IllegalStateException("Unable to build redirectUri", ex);
    }
  }

  boolean setCallerPrincipal(Subject clientSubject, GoogleUserInfo googleUserInfo) {
    final CallerPrincipalCallback principalCallback = new CallerPrincipalCallback(
            clientSubject, new GoogleOAuthPrincipal(googleUserInfo));
    final GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, new String[]{"user"});
    try {
      handler.handle(new Callback[]{principalCallback, groupCallback});
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "unable to set caller and groups", e);
      return false;
    }

    return true;
  }

  static boolean isMandatory(MessageInfo messageInfo) {
    return Boolean.valueOf((String) messageInfo.getMap().get(
            "javax.security.auth.message.MessagePolicy.isMandatory"));//FIXME don't hardcode string
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
