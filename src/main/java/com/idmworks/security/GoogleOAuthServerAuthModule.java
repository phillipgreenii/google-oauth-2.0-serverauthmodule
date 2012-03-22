package com.idmworks.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
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
    this.endpoint = retrieveOptionalProperty(options, ENDPOINT_PROPERTY_NAME, DEFAULT_ENDPOINT);
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
      final String authorizationCode = request.getParameter("code");//FIXME don't hardcode parameter name
      final String error = request.getParameter("error");//FIXME don't hardcode parameter name
      if (error != null && !error.isEmpty()) {
        LOGGER.log(Level.WARNING, "Error authorizing: {0}", new Object[]{error});
        return AuthStatus.FAILURE;
      } else {
        final String redirectUri = buildRedirectUri(request);
        final AccessTokenInfo accessTokenInfo = lookupAccessTokeInfo(redirectUri, authorizationCode);
        LOGGER.log(Level.SEVERE, "Access Token: {0}", new Object[]{accessTokenInfo});

        final GoogleUserInfo googleUserInfo = retrieveGoogleUserInfo(accessTokenInfo);

        setCallerPrincipal(clientSubject, googleUserInfo);
        return AuthStatus.SUCCESS;
      }
    } else if (isMandatory(messageInfo)) {
      return AuthStatus.SUCCESS;
    } else {
      final String redirectUri = buildRedirectUri(request);
      final String oauthUrl = buildOauthUrl(redirectUri);
      try {
        LOGGER.log(Level.FINE, "redirecting to {0} for OAuth", new Object[]{oauthUrl});
        response.sendRedirect(oauthUrl);
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + oauthUrl, ex);
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

  AccessTokenInfo lookupAccessTokeInfo(String redirectUri, String authorizationCode) {
    //FIXME don't duplicate code
    HttpsURLConnection httpsURLConnection;

    try {
      final URL url = new URL("https://accounts.google.com/o/oauth2/token");
      httpsURLConnection = (HttpsURLConnection) url.openConnection();
      httpsURLConnection.setRequestMethod("POST");
      httpsURLConnection.setDoOutput(true);
      httpsURLConnection.connect();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to connect to google api", ex);
    }

    try {
      final OutputStreamWriter out = new OutputStreamWriter(
              httpsURLConnection.getOutputStream());

      final StringBuilder sb = new StringBuilder();

      sb.append("code").append("=").append(authorizationCode);
      sb.append("&");
      sb.append("client_id").append("=").append(clientid);
      sb.append("&");
      sb.append("client_secret").append("=").append(clientSecret);
      sb.append("&");
      sb.append("redirect_uri").append("=").append(redirectUri);
      sb.append("&");
      sb.append("grant_type").append("=").append("authorization_code");
      LOGGER.severe(sb.toString());
      out.write(sb.toString());
      out.flush();
      out.close();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to POST body", ex);
    }

    try {
      LOGGER.severe("response code: " + httpsURLConnection.getResponseCode());
      if (httpsURLConnection.getResponseCode() == 200) {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(httpsURLConnection.getInputStream()));
        final StringBuilder stringBuilder = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
          stringBuilder.append(line).append("\n");
        }
        reader.close();
        return parseAccessTokenJson(stringBuilder.toString());
      } else {
        return null;//FIXME handle this better
      }
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }

  }

  GoogleUserInfo retrieveGoogleUserInfo(AccessTokenInfo accessTokenInfo) {
    //FIXME don't duplicate code
    HttpsURLConnection httpsURLConnection;

    try {
      final URL url = new URL("https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + accessTokenInfo.getAccessToken());
      httpsURLConnection = (HttpsURLConnection) url.openConnection();
      httpsURLConnection.setRequestMethod("GET");
      httpsURLConnection.setDoOutput(false);
      httpsURLConnection.connect();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to connect to google api", ex);
    }

    try {
      LOGGER.severe("response code: " + httpsURLConnection.getResponseCode());
      if (httpsURLConnection.getResponseCode() == 200) {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(httpsURLConnection.getInputStream()));
        final StringBuilder stringBuilder = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
          stringBuilder.append(line).append("\n");
        }
        reader.close();
        return parseGoogleUserInfoJson(stringBuilder.toString());
      } else {
        return null;//FIXME handle this better
      }
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }
  }

  static Map<String, String> parseSimpleJson(final String json) {
    final String[] parts = json.substring(json.indexOf("{") + 1, json.lastIndexOf("}")).split(",");

    final Map<String, String> values = new HashMap<String, String>();
    for (final String part : parts) {
      final String[] vparts = part.replaceAll("\"", "").split(":", 2);
      values.put(vparts[0].trim(), vparts[1].trim());
    }
    return values;
  }

  static AccessTokenInfo parseAccessTokenJson(final String json) {

    final Map<String, String> values = parseSimpleJson(json);

    final String accessToken = values.get("access_token");
    final String expiresInAsString = values.get("expires_in");
    final String tokenType = values.get("token_type");

    final int expiresIn = Integer.parseInt(expiresInAsString);

    return new AccessTokenInfo(accessToken, new Date(new Date().getTime() + expiresIn * 1000), tokenType);
  }

  static GoogleUserInfo parseGoogleUserInfoJson(final String json) {

    final Map<String, String> values = parseSimpleJson(json);

    final String id = values.get("id");
    final String email = values.get("email");
    final boolean verifiedEmail = values.containsKey("verified_email") && Boolean.parseBoolean(values.get("verified_email"));
    final String name = values.get("name");
    final String givenName = values.get("given_name");
    final String familyName = values.get("family_name");
    final String gender = values.get("gender");
    final String link = values.get("link");
    final String picture = values.get("picture");
    final String locale = values.get("locale");

    return new GoogleUserInfo(id, email, verifiedEmail, name, givenName, familyName, gender, link, picture, locale);
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
