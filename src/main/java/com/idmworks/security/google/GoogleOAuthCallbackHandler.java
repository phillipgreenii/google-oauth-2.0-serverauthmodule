package com.idmworks.security.google;

import com.idmworks.security.google.api.GoogleUserInfo;
import java.io.IOException;
import javax.security.auth.callback.*;

/**
 * Callback handler for {@link GoogleOAuthServerAuthModule}.
 *
 * @author pdgreen
 */
public class GoogleOAuthCallbackHandler implements CallbackHandler {

  private GoogleUserInfo googleUserInfo;

  public GoogleOAuthCallbackHandler() {
  }

  public GoogleOAuthCallbackHandler(GoogleUserInfo googleUserInfo) {
    this.googleUserInfo = googleUserInfo;
  }

  public GoogleUserInfo getGoogleUserInfo() {
    return googleUserInfo;
  }

  public void setGoogleUserInfo(GoogleUserInfo googleUserInfo) {
    this.googleUserInfo = googleUserInfo;
  }

  @Override
  public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback) {
        ((NameCallback) callback).setName(googleUserInfo.getEmail());
      } else if (callback instanceof PasswordCallback) {
        ((PasswordCallback) callback).setPassword(null);
      } else if (callback instanceof GoogleUserInfoCallBack) {
        ((GoogleUserInfoCallBack) callback).setGoogleUserInfo(googleUserInfo);
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }
}
