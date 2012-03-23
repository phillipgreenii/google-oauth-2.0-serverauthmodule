package com.idmworks.security.google;

import com.idmworks.security.google.api.GoogleUserInfo;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;

/**
 * Methods of this class connect to Google APIs. <br> Instead of including an external library to handle Google APIs,
 * and making installation/packaging more difficult, I created a couple small methods to handle it. There is only a
 * couple API calls to parse, so I felt I could by pass an external library for the sake of easier installation.
 *
 * @author pdgreen
 */
public class GoogleApiUtils {
  /*
   * User Info API
   */

  public static final String USERINFO_API_PERMISSION_EMAIL = "https://www.googleapis.com/auth/userinfo.email";
  public static final String USERINFO_API_PERMISSION_PROFILE = "https://www.googleapis.com/auth/userinfo.profile";
  public static final String USERINFO_API_URI = "https://www.googleapis.com/oauth2/v1/userinfo";
  /*
   * parameters
   */
  public static final String USERINFO_API_ID_PARAMETER = "id";
  public static final String USERINFO_API_EMAIL_PARAMETER = "email";
  public static final String USERINFO_API_VERIFIED_EMAIL_PARAMETER = "verified_email";
  public static final String USERINFO_API_NAME_PARAMETER = "name";
  public static final String USERINFO_API_GIVEN_NAME_PARAMETER = "given_name";
  public static final String USERINFO_API_FAMILY_NAME_PARAMETER = "family_name";
  public static final String USERINFO_API_GENDER_PARAMETER = "gender";
  public static final String USERINFO_API_LINK_PARAMETER = "link";
  public static final String USERINFO_API_PICTURE_PARAMETER = "picture";
  public static final String USERINFO_API_LOCALE_PARAMETER = "locale";
  /*
   * User Token API
   */
  public static final String TOKEN_API_URI = "https://accounts.google.com/o/oauth2/token";
  public static final String TOKEN_API_URI_DEFAULT_ENDPOINT = "https://accounts.google.com/o/oauth2/auth";
  /*
   * parameters
   */
  public static final String TOKEN_API_ACCESS_TYPE_PARAMETER = "access_type";
  public static final String TOKEN_API_ACCESS_TOKEN_PARAMETER = "access_token";
  public static final String TOKEN_API_APPROVAL_PROMPT_PARAMETER = "approval_prompt";
  public static final String TOKEN_API_CLIENT_ID_PARAMETER = "client_id";
  public static final String TOKEN_API_CLIENT_SECRET_PARAMETER = "client_secret";
  public static final String TOKEN_API_CODE_PARAMETER = "code";
  public static final String TOKEN_API_ERROR_PARAMETER = "error";
  public static final String TOKEN_API_EXPIRES_IN_PARAMETER = "expires_in";
  public static final String TOKEN_API_GRANT_TYPE_PARAMETER = "grant_type";
  public static final String TOKEN_API_REDIRECT_URI_PARAMETER = "redirect_uri";
  public static final String TOKEN_API_RESPONSE_TYPE_PARAMETER = "response_type";
  public static final String TOKEN_API_SCOPE_PARAMETER = "scope";
  public static final String TOKEN_API_STATE_PARAMETER = "state";
  public static final String TOKEN_API_TOKEN_TYPE_PARAMETER = "token_type";
  /*
   * values
   */
  public static final String TOKEN_API_AUTHORIZATION_CODE_VALUE = "authorization_code";
  private static final Logger LOGGER = Logger.getLogger(GoogleApiUtils.class.getName());

  public static URI buildOauthUri(final String redirectUri, final URI endpoint, final String clientid) {

    final StringBuilder querySb = new StringBuilder();
    querySb.append(TOKEN_API_SCOPE_PARAMETER).append("=").append(USERINFO_API_PERMISSION_EMAIL).append(" ").append(USERINFO_API_PERMISSION_PROFILE);
    querySb.append("&");
    querySb.append(TOKEN_API_REDIRECT_URI_PARAMETER).append("=").append(redirectUri);
    querySb.append("&");
    querySb.append(TOKEN_API_RESPONSE_TYPE_PARAMETER).append("=").append(TOKEN_API_CODE_PARAMETER);
    querySb.append("&");
    querySb.append(TOKEN_API_CLIENT_ID_PARAMETER).append("=").append(clientid);

    final String totalQuery = endpoint.getQuery() == null ? querySb.toString() : endpoint.getQuery() + "&" + querySb.toString();
    try {
      return new URI(endpoint.getScheme(), endpoint.getUserInfo(), endpoint.getHost(), endpoint.getPort(), endpoint.getPath(), totalQuery, endpoint.getFragment());
    } catch (URISyntaxException ex) {
      throw new IllegalArgumentException("Unable to build Oauth Uri", ex);
    }
  }

  static Response sendRequest(final String method, final URI destination, final String body) {
    if (LOGGER.isLoggable(Level.FINER)) {
      LOGGER.log(Level.FINER, "sendRequest({0},{1},{2})", new Object[]{method, destination, "hasBody?" + body != null});
    }

    HttpsURLConnection httpsURLConnection;

    try {
      httpsURLConnection = (HttpsURLConnection) destination.toURL().openConnection();
      httpsURLConnection.setRequestMethod(method);
      if (body != null) {
        httpsURLConnection.setDoOutput(true);
      }
      httpsURLConnection.connect();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to create connection", ex);
    }
    if (body
            != null) {
      try {
        final OutputStream out = httpsURLConnection.getOutputStream();
        LOGGER.log(Level.FINER, "body: {0}", new Object[]{body});
        out.write(body.getBytes());
        out.flush();
        out.close();
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to write body", ex);
      }
    }


    try {
      final int status = httpsURLConnection.getResponseCode();
      LOGGER.log(Level.FINER, "response code: {0}", new Object[]{status});

      final BufferedReader reader = new BufferedReader(new InputStreamReader(httpsURLConnection.getInputStream()));
      final StringBuilder stringBuilder = new StringBuilder();
      String line = null;
      while ((line = reader.readLine()) != null) {
        stringBuilder.append(line).append("\n");
      }
      reader.close();

      return new Response(status, stringBuilder.toString());
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }
  }

  static class Response {

    private final int status;
    private final String body;

    public Response(int status, String body) {
      this.status = status;
      this.body = body;
    }

    public String getBody() {
      return body;
    }

    public int getStatus() {
      return status;
    }
  }

  static Response GET(final URI destination) {
    return sendRequest("GET", destination, null);
  }

  static Response POST(final URI destination, final String body) {
    return sendRequest("POST", destination, body);
  }

  public static AccessTokenInfo lookupAccessTokeInfo(String redirectUri, String authorizationCode, String clientid, String clientSecret) {
    //FIXME cache URI
    final URI apiUri;
    try {
      apiUri = new URI(TOKEN_API_URI);
    } catch (URISyntaxException ex) {
      throw new IllegalStateException("unable to create uri for " + TOKEN_API_URI, ex);
    }

    final StringBuilder bodySb = new StringBuilder();
    bodySb.append(TOKEN_API_CODE_PARAMETER).append("=").append(authorizationCode);
    bodySb.append("&");
    bodySb.append(TOKEN_API_CLIENT_ID_PARAMETER).append("=").append(clientid);
    bodySb.append("&");
    bodySb.append(TOKEN_API_CLIENT_SECRET_PARAMETER).append("=").append(clientSecret);
    bodySb.append("&");
    bodySb.append(TOKEN_API_REDIRECT_URI_PARAMETER).append("=").append(redirectUri);
    bodySb.append("&");
    bodySb.append(TOKEN_API_GRANT_TYPE_PARAMETER).append("=").append(TOKEN_API_AUTHORIZATION_CODE_VALUE);
    LOGGER.severe(bodySb.toString());

    final Response response = POST(apiUri, bodySb.toString());

    if (response.getStatus() == 200) {
      return ParseUtils.parseAccessTokenJson(response.getBody());
    } else {
      return null;//FIXME handle this better
    }
  }

  public static GoogleUserInfo retrieveGoogleUserInfo(AccessTokenInfo accessTokenInfo) {

    final URI apiUri;
    try {
      apiUri = new URI(new StringBuilder(USERINFO_API_URI).append("?").append(TOKEN_API_ACCESS_TOKEN_PARAMETER).append("=").append(accessTokenInfo.getAccessToken()).toString());
    } catch (URISyntaxException ex) {
      throw new IllegalStateException("unable to create uri for " + USERINFO_API_URI, ex);
    }

    final Response response = GET(apiUri);

    if (response.getStatus() == 200) {
      return ParseUtils.parseGoogleUserInfoJson(response.getBody());
    } else {
      return null;//FIXME handle this better
    }

  }
}
