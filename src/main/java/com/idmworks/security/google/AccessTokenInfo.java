package com.idmworks.security.google;

import java.util.Date;

/**
 * Information about access token;
 *
 * @author pdgreen
 */
public class AccessTokenInfo {

  private final String accessToken;
  private final Date expiration;
  private final String type;

  public AccessTokenInfo(String accessToken, Date expiration, String type) {
    this.accessToken = accessToken;
    this.expiration = expiration;
    this.type = type;
  }

  public String getAccessToken() {
    return accessToken;
  }

  public Date getExpiration() {
    return expiration;
  }

  public String getType() {
    return type;
  }

  @Override
  public String toString() {
    return getAccessToken();
  }
}
