package com.idmworks.security.google;

import com.idmworks.security.google.api.GoogleUserInfo;
import java.io.Serializable;
import javax.security.auth.callback.Callback;

/**
 * Callback for GoogleUserInfo.
 *
 * @author pdgreen
 */
public class GoogleUserInfoCallBack implements Callback, Serializable {

  private GoogleUserInfo googleUserInfo;

  public GoogleUserInfo getGoogleUserInfo() {
    return googleUserInfo;
  }

  void setGoogleUserInfo(GoogleUserInfo googleUserInfo) {
    this.googleUserInfo = googleUserInfo;
  }
}
