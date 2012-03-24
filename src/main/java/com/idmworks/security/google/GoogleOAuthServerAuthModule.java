package com.idmworks.security.google;

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

  /*
   * SAM Constants
   */
  private static final String IS_MANDATORY_INFO_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
  private static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
  private static final String AUTH_TYPE_GOOGLE_OAUTH_KEY = "Google-OAuth";
  /*
   * defaults
   */
  public static final String DEFAULT_OAUTH_CALLBACK_PATH = "/j_oauth_callback";
  /*
   * property names
   */
  private static final String ENDPOINT_PROPERTY_NAME = "oauth.endpoint";
  private static final String CLIENTID_PROPERTY_NAME = "oauth.clientid";
  private static final String CLIENTSECRET_PROPERTY_NAME = "oauth.clientsecret";
  private static final String CALLBACK_URI_PROPERTY_NAME = "oauth.callback_uri";
  private static final String DEFAULT_GROUPS_PROPERTY_NAME = "default_groups";
  private static Logger LOGGER = Logger.getLogger(GoogleOAuthServerAuthModule.class.getName());
  protected static final Class[] SUPPORTED_MESSAGE_TYPES = new Class[]{
    javax.servlet.http.HttpServletRequest.class,
    javax.servlet.http.HttpServletResponse.class};
  private CallbackHandler handler;
  //properties
  private String clientid;
  private String clientSecret;
  private URI endpoint;
  private String oauthAuthenticationCallbackUri;
  private String defaultGroups;

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
      LOGGER.log(Level.SEVERE, message);
      throw new AuthException(message);
    }
  }

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
    this.handler = handler;
    //properties
    this.clientid = retrieveRequiredProperty(options, CLIENTID_PROPERTY_NAME);
    this.clientSecret = retrieveRequiredProperty(options, CLIENTSECRET_PROPERTY_NAME);
    try {
      this.endpoint = new URI(retrieveOptionalProperty(options, ENDPOINT_PROPERTY_NAME, GoogleApiUtils.TOKEN_API_URI_DEFAULT_ENDPOINT));
    } catch (URISyntaxException ex) {
      final String message = String.format("Invalid field '%s'", ENDPOINT_PROPERTY_NAME);
      LOGGER.log(Level.SEVERE, message, ex);
      final AuthException aex = new AuthException(message);
      aex.initCause(ex);
      throw aex;
    }
    this.oauthAuthenticationCallbackUri = retrieveOptionalProperty(options, CALLBACK_URI_PROPERTY_NAME, DEFAULT_OAUTH_CALLBACK_PATH);
    this.defaultGroups = retrieveOptionalProperty(options, DEFAULT_GROUPS_PROPERTY_NAME, "");
    LOGGER.log(Level.FINE, "{0} initialized", new Object[]{GoogleOAuthServerAuthModule.class.getSimpleName()});
  }

  @Override
  public Class[] getSupportedMessageTypes() {
    return SUPPORTED_MESSAGE_TYPES;
  }

  @Override
  public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
    LOGGER.log(Level.FINER, "validateRequest({0}, {1}, {2})", new Object[]{messageInfo, clientSubject, serviceSubject});

    final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
    final HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

    if (isOauthResponse(request)) {
      return handleOauthResponse(messageInfo, request, response, clientSubject);
    } else if (isMandatory(messageInfo)) {
      return handleMandatoryRequest(messageInfo, request, response, clientSubject);
    } else {
      return AuthStatus.SUCCESS;
    }
  }

  AuthStatus handleOauthResponse(final MessageInfo messageInfo, final HttpServletRequest request, final HttpServletResponse response, final Subject clientSubject) {
    final String authorizationCode = request.getParameter(GoogleApiUtils.TOKEN_API_CODE_PARAMETER);
    final String error = request.getParameter(GoogleApiUtils.TOKEN_API_ERROR_PARAMETER);
    if (error != null && !error.isEmpty()) {
      LOGGER.log(Level.WARNING, "Error authorizing: {0}", new Object[]{error});
      //FIXME add an error page configuration  and return SEND_FAILURE (how do you use FAILURE?  it returns blank page)
      return AuthStatus.FAILURE;
    } else {
      final String redirectUri = buildRedirectUri(request);
      final AccessTokenInfo accessTokenInfo = GoogleApiUtils.lookupAccessTokenInfo(redirectUri, authorizationCode, clientid, clientSecret);
      LOGGER.log(Level.FINE, "Access Token: {0}", new Object[]{accessTokenInfo});

      final GoogleUserInfo googleUserInfo = GoogleApiUtils.retrieveGoogleUserInfo(accessTokenInfo);
      if (googleUserInfo == null) {
        //FIXME handle failure better
        return AuthStatus.SEND_FAILURE;
      } else {
        authenticate(messageInfo, request, response, clientSubject, googleUserInfo);
        return AuthStatus.SEND_CONTINUE;
      }
    }
  }

  void authenticate(final MessageInfo messageInfo, final HttpServletRequest request, final HttpServletResponse response, final Subject subject, final GoogleUserInfo googleUserInfo) {
    final StateHelper stateHelper = new StateHelper(request);

    setCallerPrincipal(subject, googleUserInfo);
    messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, AUTH_TYPE_GOOGLE_OAUTH_KEY);
    stateHelper.saveSubject(subject);

    final URI orignalRequestUri = stateHelper.extractOriginalRequestPath();
    if (orignalRequestUri != null) {
      try {
        LOGGER.log(Level.FINE, "redirecting to original request path: {0}", orignalRequestUri);
        response.sendRedirect(orignalRequestUri.toString());
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + orignalRequestUri, ex);
      }

    }
  }

  AuthStatus handleMandatoryRequest(final MessageInfo messageInfo, final HttpServletRequest request, final HttpServletResponse response, final Subject clientSubject) {
    final StateHelper stateHelper = new StateHelper(request);

    final Subject savedSubject = stateHelper.retrieveSavedSubject();
    if (savedSubject != null) {
      LOGGER.log(Level.FINE, "Applying saved subject: {0}", savedSubject);
      applySubject(savedSubject, clientSubject);
      return AuthStatus.SUCCESS;
    } else {
      stateHelper.saveOriginalRequestPath();
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

    final Callback[] callbacks;
    if (defaultGroups.isEmpty()) {
      callbacks = new Callback[]{principalCallback};
    } else {
      final GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, defaultGroups.split(","));
      callbacks = new Callback[]{principalCallback, groupCallback};
    }

    try {
      handler.handle(callbacks);
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "unable to set caller and groups", e);
      return false;
    }

    return true;
  }

  static void applySubject(final Subject source, Subject destination) {
    destination.getPrincipals().addAll(
            source.getPrincipals());
    destination.getPublicCredentials().addAll(source.getPublicCredentials());
    destination.getPrivateCredentials().addAll(source.getPrivateCredentials());
  }

  static boolean isMandatory(MessageInfo messageInfo) {
    return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY_INFO_KEY));
  }

  @Override
  public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
    return AuthStatus.SEND_SUCCESS;
  }

  @Override
  public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    //TODO do i need to check messageInfo so that i only remove the specific GoogleOAuthPrincipal instance?
    //TODO remove groups?
    subject.getPrincipals().removeAll(subject.getPrincipals(GoogleOAuthPrincipal.class));
  }
}
