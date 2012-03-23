package com.idmworks.security.google;

import com.idmworks.security.google.api.GoogleUserInfo;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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

  public static URI buildOauthUri(final String redirectUri, final String endpoint, final String clientid) {

    final StringBuilder sb = new StringBuilder(endpoint);
    sb.append("?");
    sb.append(TOKEN_API_SCOPE_PARAMETER).append("=").append(USERINFO_API_PERMISSION_EMAIL).append(" ").append(USERINFO_API_PERMISSION_PROFILE);
    sb.append("&");
    sb.append(TOKEN_API_REDIRECT_URI_PARAMETER).append("=").append(redirectUri);
    sb.append("&");
    sb.append(TOKEN_API_RESPONSE_TYPE_PARAMETER).append("=").append(TOKEN_API_CODE_PARAMETER);
    sb.append("&");
    sb.append(TOKEN_API_CLIENT_ID_PARAMETER).append("=").append(clientid);
    try {
      return new URI(sb.toString());
    } catch (URISyntaxException ex) {
      throw new IllegalArgumentException("Unable to build Oauth Uri", ex);
    }
  }

  public static AccessTokenInfo lookupAccessTokeInfo(String redirectUri, String authorizationCode, String clientid, String clientSecret) {
    //FIXME don't duplicate code
    HttpsURLConnection httpsURLConnection;

    try {
      final URL url = new URL(TOKEN_API_URI);
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

      sb.append(TOKEN_API_CODE_PARAMETER).append("=").append(authorizationCode);
      sb.append("&");
      sb.append(TOKEN_API_CLIENT_ID_PARAMETER).append("=").append(clientid);
      sb.append("&");
      sb.append(TOKEN_API_CLIENT_SECRET_PARAMETER).append("=").append(clientSecret);
      sb.append("&");
      sb.append(TOKEN_API_REDIRECT_URI_PARAMETER).append("=").append(redirectUri);
      sb.append("&");
      sb.append(TOKEN_API_GRANT_TYPE_PARAMETER).append("=").append(TOKEN_API_AUTHORIZATION_CODE_VALUE);
      LOGGER.severe(sb.toString());
      out.write(sb.toString());
      out.flush();
      out.close();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to POST body", ex);
    }

    try {
      LOGGER.log(Level.FINE, "response code: {0}", new Object[]{httpsURLConnection.getResponseCode()});
      if (httpsURLConnection.getResponseCode() == 200) {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(httpsURLConnection.getInputStream()));
        final StringBuilder stringBuilder = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
          stringBuilder.append(line).append("\n");
        }
        reader.close();
        return ParseUtils.parseAccessTokenJson(stringBuilder.toString());
      } else {
        return null;//FIXME handle this better
      }
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }

  }

  public static GoogleUserInfo retrieveGoogleUserInfo(AccessTokenInfo accessTokenInfo) {
    //FIXME don't duplicate code
    HttpsURLConnection httpsURLConnection;

    try {
      final URL url = new URL(new StringBuilder(USERINFO_API_URI).append("?").append(TOKEN_API_ACCESS_TYPE_PARAMETER).append("=").append(accessTokenInfo.getAccessToken()).toString());
      httpsURLConnection = (HttpsURLConnection) url.openConnection();
      httpsURLConnection.setRequestMethod("GET");
      httpsURLConnection.setDoOutput(false);
      httpsURLConnection.connect();
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to connect to google api", ex);
    }

    try {
      LOGGER.log(Level.FINE, "response code: {0}", new Object[]{httpsURLConnection.getResponseCode()});
      if (httpsURLConnection.getResponseCode() == 200) {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(httpsURLConnection.getInputStream()));
        final StringBuilder stringBuilder = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
          stringBuilder.append(line).append("\n");
        }
        reader.close();
        return ParseUtils.parseGoogleUserInfoJson(stringBuilder.toString());
      } else {
        return null;//FIXME handle this better
      }
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }
  }
}
