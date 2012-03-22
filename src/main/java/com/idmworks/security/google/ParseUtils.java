package com.idmworks.security.google;

import com.idmworks.security.AccessTokenInfo;
import com.idmworks.security.GoogleUserInfo;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Methods of this class parse JSON responses. <br> Instead of including an external library to handle JSON, and making
 * installation/packaging more difficult, I created a couple small methods to handle it. There is only a couple response
 * to parse, so I felt I could by pass a full JSON parse for the sake of easier installation.
 *
 * @author pdgreen
 */
public class ParseUtils {

  static Map<String, String> parseSimpleJson(final String json) {
    final String[] parts = json.substring(json.indexOf("{") + 1, json.lastIndexOf("}")).split(",");

    final Map<String, String> values = new HashMap<String, String>();
    for (final String part : parts) {
      final String[] vparts = part.replaceAll("\"", "").split(":", 2);
      values.put(vparts[0].trim(), vparts[1].trim());
    }
    return values;
  }

  public static AccessTokenInfo parseAccessTokenJson(final String json) {

    final Map<String, String> values = parseSimpleJson(json);

    final String accessToken = values.get("access_token");
    final String expiresInAsString = values.get("expires_in");
    final String tokenType = values.get("token_type");

    final int expiresIn = Integer.parseInt(expiresInAsString);

    return new AccessTokenInfo(accessToken, new Date(new Date().getTime() + expiresIn * 1000), tokenType);
  }

  public static GoogleUserInfo parseGoogleUserInfoJson(final String json) {

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
}
