package com.idmworks.security;

import org.junit.*;
import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

/**
 * Tests for {@link GoogleOAuthServerAuthModule}.
 *
 * @author pdgreen
 */
public class GoogleOAuthServerAuthModuleTest {

  @Test
  public void testParseAccessTokenJson() {
    String json =
            "{\n"
            + "\"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\n"
            + "\"expires_in\":3920,\n"
            + "\"token_type\":\"Bearer\"\n"
            + "}";

    final AccessTokenInfo result = GoogleOAuthServerAuthModule.parseAccessTokenJson(json);

    assertThat(result, is(notNullValue()));
    assertThat(result.getAccessToken(), is("1/fFAGRNJru1FTz70BzhT3Zg"));
    assertThat(result.getType(), is("Bearer"));
  }

  @Test
  public void testParseGoogleUserInfoJson() {
    String json =
            "{\n"
            + "\"id\": \"1074968992519869407200\",\n"
            + "\"email\": \"fake.name@gmail.com\",\n"
            + "\"verified_email\": true,\n"
            + "\"name\": \"Fake Name\",\n"
            + "\"given_name\": \"Fake\",\n"
            + "\"family_name\": \"Name\",\n"
            + "\"link\": \"https://plus.google.com/1074968992519869407200\",\n"
            + "\"picture\": \"https://lh4.googleusercontent.com/path/to/photo.jpg\",\n"
            + "\"gender\": \"other\",\n"
            + "\"locale\": \"en-US\"\n"
            + "}";

    final GoogleUserInfo result = GoogleOAuthServerAuthModule.parseGoogleUserInfoJson(json);

    assertThat(result, is(notNullValue()));
    assertThat(result.getId(), is("1074968992519869407200"));
    assertThat(result.getEmail(), is("fake.name@gmail.com"));
    assertThat(result.isVerifiedEmail(), is(true));
    assertThat(result.getName(), is("Fake Name"));
    assertThat(result.getGivenName(), is("Fake"));
    assertThat(result.getFamilyName(), is("Name"));
    assertThat(result.getGender(), is("other"));
    assertThat(result.getLink(), is("https://plus.google.com/1074968992519869407200"));
    assertThat(result.getPicture(), is("https://lh4.googleusercontent.com/path/to/photo.jpg"));
    assertThat(result.getLocale(), is("en-US"));
  }
}
