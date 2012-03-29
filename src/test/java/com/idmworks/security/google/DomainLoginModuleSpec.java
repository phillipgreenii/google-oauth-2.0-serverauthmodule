package com.idmworks.security.google;

import com.idmworks.security.google.GoogleOAuthCallbackHandler;
import com.idmworks.security.google.api.GoogleUserInfo;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.junit.*;

import static org.mockito.Mockito.*;

/**
 * Specification for {@link DomainLoginModule}.
 *
 * @author pdgreen
 */
public class DomainLoginModuleSpec {

  static String getResourcePath(final String resourceName) {
    return DomainLoginModuleSpec.class.getClassLoader().getResource(resourceName).getPath();
  }

  @Test(expected = LoginException.class)
  public void loginContextLoginShouldFailWithInvalidDomain() throws LoginException {
    final String oldValue = System.getProperty("java.security.auth.login.config");
    System.setProperty("java.security.auth.login.config", getResourcePath("test.config"));

    final GoogleUserInfo mockUserInfo = mock(GoogleUserInfo.class);
    when(mockUserInfo.getEmail()).thenReturn("fake");

    try {
      LoginContext lc = new LoginContext("test-DomainLoginModule", new GoogleOAuthCallbackHandler(mockUserInfo));
      lc.login();
    } finally {
      if (oldValue != null) {
        System.setProperty("java.security.auth.login.config", oldValue);

      }
    }
  }

  @Test
  public void loginContextLoginShouldSuccessWithValidDomain() throws LoginException {
    final String oldValue = System.getProperty("java.security.auth.login.config");
    System.setProperty("java.security.auth.login.config", getResourcePath("test.config"));

    final GoogleUserInfo mockUserInfo = mock(GoogleUserInfo.class);
    when(mockUserInfo.getEmail()).thenReturn("fake@idmworks.com");

    try {
      LoginContext lc = new LoginContext("test-DomainLoginModule", new GoogleOAuthCallbackHandler(mockUserInfo));
      lc.login();
    } finally {
      if (oldValue != null) {
        System.setProperty("java.security.auth.login.config", oldValue);

      }
    }
  }
}
