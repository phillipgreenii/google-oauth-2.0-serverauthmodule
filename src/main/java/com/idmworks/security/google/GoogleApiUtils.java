package com.idmworks.security.google;

import com.idmworks.security.AccessTokenInfo;
import com.idmworks.security.google.api.GoogleUserInfo;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
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

  private static Logger LOGGER = Logger.getLogger(GoogleApiUtils.class.getName());

  public static String buildOauthUrl(final String redirectUri, final String endpoint, final String clientid) {

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

  public static AccessTokenInfo lookupAccessTokeInfo(String redirectUri, String authorizationCode, String clientid, String clientSecret) {
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
        return ParseUtils.parseGoogleUserInfoJson(stringBuilder.toString());
      } else {
        return null;//FIXME handle this better
      }
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to read response", ex);
    }
  }
}
