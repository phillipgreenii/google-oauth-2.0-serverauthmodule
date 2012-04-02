Overview
========


Google OAuth 2.0 ServerAuthModule is a ServerAuthModule (SAM), [JSR-196 (JASPIC) Spec][jsr-196], implementation of [Google OAuth 2.0][google-oauth]: `com.idmworks.security.google.GoogleOAuthServerAuthModule`.  It optionally supports the [LoginModule Bridge Profile].

Installation
============

Copy `google-oauth-2_0-sam-0.1.x.jar` into the class path of the application server.  See [Installation](https://bitbucket.org/phillip_green_idmworks/google-oauth-2.0-serverauthmodule/wiki/setup/1-installation) for application server specific instructions.


Configuration
=============

Before you can authenticate with Google OAuth, you will need to create a Client ID for your web application at [Client ID API Console][google-api-console].

Next, the GoogleOAuthServerAuthModule needs added to the application server.  See [Configuration](https://bitbucket.org/phillip_green_idmworks/google-oauth-2.0-serverauthmodule/wiki/setup/2-configuration) for application server specific instructions.


### GoogleOAuthServerAuthModule

The following attributes can be used to configure `com.idmworks.security.google.GoogleOAuthServerAuthModule`.

#### `oauth.clientid` (_REQUIRED_)
`oauth.clientid` must be set to a "`Client ID`" from [Client ID API Console][google-api-console].

#### `oauth.clientsecret` (_REQUIRED_)
`oauth.clientsecret` must be set to the "`Client Secret`" from [Client ID API Console][google-api-console] of the "`Client ID`" specified in `oauth.clientid`.


#### `oauth.endpoint` (_optional_)
default: `https://accounts.google.com/o/oauth2/auth`

`oauth.endpoint` is the URI that will be connect to for the OAuth authentication (Google).

#### `oauth.callback_uri` (_optional_) 
default: `/j_oauth_callback`

`oauth.callback_uri` is the URI that Google will redirect to after the user responds to the request.  This should correspond to "`Redirect URIs`" value defined in the [Client ID API Console][google-api-console].

#### `javax.security.auth.login.LoginContext` (_optional_)
default: `"com.idmworks.security.google.GoogleOAuthServerAuthModule"`

With [LoginModule Bridge Profile], `javax.security.auth.login.LoginContext` is where you define the name of the [LoginContext][javadocs-logincontext] to use.

#### `ignore_missing_login_context` (_optional_)
default: `"false"`

`GoogleOAuthServerAuthModule` is configured to optionally support [LoginModule Bridge Profile].  If you set `ignore_missing_login_context` to false (in the case when you don't want to use any [LoginModules][javadocs-loginmodule]), there will be no error when a LoginContext isn't found.


#### `add_domain_as_group` (_optional_)
default: `"false"`

If `add_domain_as_group` is `true`, then the domain of the email address of the authenticated user will be added as a group.  IE: "idmworks.com" will be a principal added as a group for the user "phillip.green@idmworks.com".



#### `default_groups` (_optional_)
default: `""`

`default_groups` is a comma (",") separated list of groups that will be given to the principal upon successful authentication.

Usage
=====

The configured `GoogleOAuthServerAuthModule` needs specified in the application server specific configuration for each application.   See [Usage](https://bitbucket.org/phillip_green_idmworks/google-oauth-2.0-serverauthmodule/wiki/setup/3-usage) for application server specific instructions.

Common Problems
===============
See [Common Problems](https://bitbucket.org/phillip_green_idmworks/google-oauth-2.0-serverauthmodule/wiki/common-problems).


References
==========
  + [JSR-196][jsr-196]
  + [Google API Console][google-api-console]
  + [Google OAuth][google-oauth]
  + [Google OAuth for Webservers][google-oauth-webserver]
  + [LoginContext Javadocs][javadocs-logincontext]
  + [LoginModule Javadocs][javadocs-loginmodule]
  + [LoginModule Bridge Profile in glassfish][LoginModule Bridge Profile]
  + [LoginContext Configuration][configuration-logincontext]
  + [configuration-logincontext]
  + [openid4java-jsr196]
  + [Project Source Code on Bitbucket][bitbucket-source]

  [jsr-196]: http://www.jcp.org/en/jsr/detail?id=196
  [google-api-console]: https://code.google.com/apis/console/
  [google-oauth]: https://developers.google.com/accounts/docs/OAuth2  
  [google-oauth-webserver]: https://developers.google.com/accounts/docs/OAuth2WebServer
  [javadocs-logincontext]: http://docs.oracle.com/javase/6/docs/api/javax/security/auth/login/LoginContext.html
  [javadocs-loginmodule]: http://docs.oracle.com/javase/6/docs/api/javax/security/auth/spi/LoginModule.html
  [LoginModule Bridge Profile]: https://blogs.oracle.com/nasradu8/entry/loginmodule_bridge_profile_jaspic_in
  [configuration-logincontext]: http://docs.oracle.com/javase/6/docs/api/javax/security/auth/login/Configuration.html
  [openid4java-jsr196]: http://code.google.com/p/openid4java-jsr196/
  [bitbucket-source]: https://bitbucket.org/phillip_green_idmworks/gooogle-oauth-2.0-serverauthmodule