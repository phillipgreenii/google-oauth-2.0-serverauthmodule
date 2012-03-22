package com.idmworks.security;

import org.junit.*;
import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

/**
 * Tests for {@link GoogleOAuthServerAuthModule}.
 * @author pdgreen
 */
public class GoogleOAuthServerAuthModuleTest {

  /**
   * Test of parseAccessTokenJson method, of class GoogleOAuthServerAuthModule.
   */
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
}
