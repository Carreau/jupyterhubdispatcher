# Jupyterhub Dispatcher. 

An attempt to make a Hub placeholder that only Authenticate the users.

This is 3 things: 
 - A Phony spawner that does nothing, 
 - A Proxy Authenticator that wrap set authenticators to intercept the
   set_login_cookie to set a cookie for the proxy to know to which hub to
   dispatch. 

A strip down version of the JupyterHub application that does not do some stuff
(like services etc... but this appear to be a rat's nest and we've reimplemented
half if not more of it), so having that as a JupyterHub sub (or super) class is
not out of question.
