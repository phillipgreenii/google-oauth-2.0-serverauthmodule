package com.idmworks.security;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;

/**
 * SAM ({@link ServerAuthModule}) for Google OAuth.
 *
 * @author pdgreen
 */
public class GoogleOAuthServerAuthModule implements ServerAuthModule {

  private static Logger LOGGER = Logger.getLogger(GoogleOAuthServerAuthModule.class.getName());
  protected static final Class[] SUPPORTED_MESSAGE_TYPES = new Class[]{
    javax.servlet.http.HttpServletRequest.class,
    javax.servlet.http.HttpServletResponse.class};
  private MessagePolicy requestPolicy;
  private MessagePolicy responsePolicy;
  private CallbackHandler handler;
  private Map<String, String> options;
  private boolean mandatory;

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
    this.requestPolicy = requestPolicy;
    this.responsePolicy = responsePolicy;
    this.handler = handler;
    this.options = options;
    this.mandatory = requestPolicy.isMandatory();
  }

  @Override
  public Class[] getSupportedMessageTypes() {
    return SUPPORTED_MESSAGE_TYPES;
  }

  @Override
  public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

    setCallerPrincipal(clientSubject, "test-user@gmail.com");

    return AuthStatus.SUCCESS;
  }

  boolean setCallerPrincipal(Subject clientSubject, String email) {
    final CallerPrincipalCallback principalCallback = new CallerPrincipalCallback(
            clientSubject, new GoogleOAuthPrincipal(email));
    final GroupPrincipalCallback groupCallback = new GroupPrincipalCallback(clientSubject, new String[]{"user"});
    try {
      handler.handle(new Callback[]{principalCallback, groupCallback});
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "unable to set caller and groups", e);
      return false;
    }

    return true;
  }

  @Override
  public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
    //TODO what needs to happen here?
    return AuthStatus.SEND_SUCCESS;
  }

  @Override
  public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    //TODO do i need to check messageInfo so that i only remove the specific GoogleOAuthPrincipal instance?
    subject.getPrincipals().removeAll(subject.getPrincipals(GoogleOAuthPrincipal.class));
  }
}
