package com.idmworks.security.google.api;

/**
 * User information from google account.
 *
 * @author pdgreen
 */
public class GoogleUserInfo {

  private final String id;
  private final String email;
  private final boolean verifiedEmail;
  private final String name;
  private final String givenName;
  private final String familyName;
  private final String gender;
  private final String link;
  private final String picture;
  private final String locale;

  public GoogleUserInfo(String id, String email, boolean verifiedEmail, String name, String givenName, String familyName, String gender, String link, String picture, String locale) {
    this.id = id;
    this.email = email;
    this.verifiedEmail = verifiedEmail;
    this.name = name;
    this.givenName = givenName;
    this.familyName = familyName;
    this.gender = gender;
    this.link = link;
    this.picture = picture;
    this.locale = locale;
  }

  public String getEmail() {
    return email;
  }

  public String getFamilyName() {
    return familyName;
  }

  public String getGender() {
    return gender;
  }

  public String getGivenName() {
    return givenName;
  }

  public String getId() {
    return id;
  }

  public String getLink() {
    return link;
  }

  public String getLocale() {
    return locale;
  }

  public String getName() {
    return name;
  }

  public String getPicture() {
    return picture;
  }

  public boolean isVerifiedEmail() {
    return verifiedEmail;
  }
}
