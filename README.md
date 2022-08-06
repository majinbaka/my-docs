# secure-checklist

### Use newest PHP version if it possible
> PHP 7 includes a range of built-in security-specific improvements (such as libsodium in
PHP 7.2) and deprecates older, insecure features and functionality. As a result, it is far
easier to create more secure applications with PHP 7, than any previous version of PHP.
Use it whenever possible.

###  Use a SAST
> A SAST is a Static Application Security Tester (or testing service). A SAST scans source
code looking for vulnerable code or potentially vulnerable code. But the number of false
positives and false negatives makes it hard to trust.
- [SAST, DAST, and RASP: A guide to the new security alphabet soup](https://blog.sqreen.io/sast-dast-rasp/)

### Use a DAST
> A DAST is a Dynamic Application Security Tester (or testing service). A DAST searches
for weaknesses and vulnerabilities in running applications. But the number of false
positives and false negatives makes it hard to trust.
- [Common Approaches to Automated Application Security Testing - SAST andDAST](https://www.securityweek.com/common-approaches-automated-application-security-testing-sast-and-dast)

### Filter and Validate All Data 
 
> Regardless of where the data comes from, whether that’s a configuration file, server
environment, GET and POST, or anywhere else, do not trust it. Filter and validate it! Do
this by using one of the available libraries, such as zend-inputfilter. 

### Whitelist, Never Blacklist
> Never attempt to filter out unacceptable input. Just filter for only what is acceptable. To
attempt to filter out anything that is unacceptable leads to unnecessarily complicated
code, which likely leads to defects and security flaws. 
- [PHP Security - Never Blacklist; Only Whitelist](http://phpsecurity.readthedocs.io/en/latest/Input-Validation.html#never-blacklist-only-whitelist)
### Use Parameterized Queries 
> To avoid SQL injection attacks, never concatenate or interpolate SQL strings with
external data. Use parameterized queries instead and prepared statements. These can be
used with vendor-specific libraries or by using PDO.
- [Prepared statements and stored procedures in PDO](https://secure.php.net/manual/en/pdo.prepared-statements.php)
- [Mysqli Prepared Statements](https://secure.php.net/manual/de/mysqli.quickstart.prepared-statements.php)
- [The PostgreSQL pg_query_params function](https://secure.php.net/manual/en/function.pg-query-params.php)

### Use an ORM 
> Take parameterized queries and prepared statements one step further, and avoid, if at all
possible, writing SQL queries yourself, by using an ORM; one scrutinized and tested by
many security-conscious developers. 
- [ORM](http://www.doctrine-project.org/projects/orm.html)

### Use Libsodium 
> As of PHP 7.2, older encryption libraries have been deprecated, such as Mcrypt.
However, PHP 7.2 supports the far better Libsodium library instead. Now, out of the box,
developers can make use of modern cryptography with next to no knowledge of
cryptography. 

### Set open_basedir 
> The `open_basedir` directive limits the files that PHP can access to the filesystem from
the `open_basedir` directory and downward. No files or directories outside of that
directory can be accessed. That way, if malicious users attempt to access sensitive files,
such as `/etc/passwd`, access will be denied.

### Make sure permissions on filesystem are limited 
> PHP scripts should only be able to write in places you need to upload files of specifically
write files. This places should not be anywhere a PHP script can be executed by the
server. Else, it open the way for an attacker to write a PHP file somewhere and to run
arbitrary PHP code.

- [OWASP filesystem guide](https://www.owasp.org/index.php/File_System)

### Perform Strict Type Comparisons 
> If weak type checking is used, such as with the `==` operator, vulnerabilities can occur due
to the often peculiar ways that PHP converts types. These include 1.14352 being
converted to 1, strings converting to 1, “1is this true” converts to true, and so on. This is
because according to the manual:
> By default, PHP will coerce values of the wrong type into the expected scalar type if
possible.
> Use strict type checking to ensure that when comparing two items that they are of the
same type. And in PHP 7.1, use `declare (strict_types=1);`. 
- [PHP 7 type hinting: inconsistencies and pitfalls](http://web-techno.net/typing-with-php-7-what-you-shouldnt-do/)
- [PHP strict typing](https://secure.php.net/manual/en/functions.arguments.php#functions.arguments.type-declaration.strict)

### Use libxml_disable_entity_loader(true)

> To avoid XML External Entity Injections, when working with XML content, use
`libxml_disable_entity_loader` to disable external entity resolution. 

- [XML external entity attack](https://en.wikipedia.org/wiki/XML_external_entity_attack)
- [XML External Entity (XXE) Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#PHP)
- [libxml_disable_entity_loader](https://secure.php.net/manual/de/function.libxml-disable-entity-loader.php)

### Don’t Implement Your Own Crypto 
> Unless you’re a security expert—and even if you are—never implement your own crypto.
This is a common cause of security errors, as too few eyes have had a chance to review
the code. Instead, use a publicly reviewed, critiqued, and tested library, such as Libsodium
in PHP 7.2.
- [Why is writing your own encryption discouraged?](https://crypto.stackexchange.com/questions/43272/why-is-writing-your-own-encryption-discouraged)
- [Why shouldn’t we roll our own (cryptography)?](https://security.stackexchange.com/questions/18197/why-shouldnt-we-roll-our-own)
- [Why You Don’t Roll Your Own Crypto](https://motherboard.vice.com/en_us/article/wnx8nq/why-you-dont-roll-your-own-crypto)

###  Integrate Security Scanners Into Your CI Pipeline
> Security scanners can help to detect questionable code and code that contains obvious
security defects. Continuous Integration (CI) tools can use these scanners to test your
code and fail the build if the scanner meets or surpasses acceptable thresholds
- [ircmaxell/php-security-scanner](https://github.com/ircmaxell/php-security-scanner)
- [PHP Quality Assurance](https://phpqa.io/index.html)

### Keep All Dependencies Up to Date
> Most PHP code relies on external, third-party dependencies. However, these need to be
kept up to date, wherever possible, to ensure that any bug and security fixes are available
to your code. Ensure you’re using Composer as your dependency manager and keep up to
date with all of your dependencies.
- [Composer basic usage](https://getcomposer.org/doc/01-basic-usage.md)

### Invalidate Sessions When Required
> After any significant application state change, such as a password change, password
update, or security errors, expire and destroy the session.
- [session_regenerate_id](https://secure.php.net/manual/en/function.session-regenerate-id.php)
- [PHP Session Security Best Practices](https://github.com/sobstel/sesshin/wiki/PHP-Session-Security---Best-Practices)

### Never Store Sensitive Data in Session
> No sensitive data—ideally only a minimum of data or the session id—should ever be
stored in a session.
- [Session hijacking attack](https://www.owasp.org/index.php/Session_hijacking_attack)
- [Session fixation attack](https://www.owasp.org/index.php/Session_fixation)
- [OWASP Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

### Never Store Sessions in a Shared Area
> It has been common, when using shared hosting providers, for PHP to be automatically
configured to store sessions on the filesystem, in the same directory. Never do this.
Always check your configuration and store session information in a private location,
accessible only by your application.
- [Shared Hosting: PHP Session Security](https://websec.io/2012/08/24/Shared-Hosting-PHP-Session-Security.html)
- [Custom Session Handlers](https://secure.php.net/manual/en/session.customhandler.php)
- [Storing sessions in Memcache](https://secure.php.net/manual/en/memcached.sessions.php)
- [How to Set Up a Redis Server as a Session Handler for PHP](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-redis-server-as-a-session-handler-for-php-on-ubuntu-14-04)
- [PHP-MySQL-Sessions](https://github.com/dominicklee/PHP-MySQL-Sessions)

### Use Secure Session Settings
> When using sessions make sure that you configure them to be as secure as possible to
prevent as many attacks as you practically can. This includes locking a session to a domain
or IP address, don’t permanently store cookies, use secure cookies (sent over HTTPS),
use large session `sid_length` and `sid_bits_per_character` values.
- [https://secure.php.net/manual/en/session.security.ini.php](https://secure.php.net/manual/en/session.security.ini.php)
- [Session Management Basics](https://secure.php.net/manual/en/features.session.security.management.php)

### Don’t Cache Sensitive Data
> When you cache data to speed up your application, such as database requests, ensure
that sensitive data isn’t cached.
- [Best practice for caching sensitive data](https://security.stackexchange.com/questions/87144/best-practice-for-caching-sensitive-data)
### Store Passwords Using Strong Hashing Functions
> Ensure that all passwords and other potentially sensitive data are hashed, using robust
hashing functions such as bcrypt. Don’t use weak hashing functions, such as MD5 and
SHA1.
- [Use Bcrypt or Scrypt Instead of SHA* for Your Passwords, Please!](https://rietta.com/blog/2016/02/05/bcrypt-not-sha-for-passwords/)
- [The Dangers of Weak Hashes](https://www.sans.org/reading-room/whitepapers/authentication/dangers-weak-hashes-34412)
### Use a Reputable ACL or RBAC Library
> To ensure that access to sensitive data is both authenticated and authorized, use mature
ACL (Access Control Library) and RBAC (Role Based Access Control) packages.

- [PHP-RBAC8](http://phprbac.net/)
- [zend-authentication](https://docs.zendframework.com/zend-authentication/)
- [Symfony Authentication](https://symfony.com/doc/current/components/security/authentication.html)
- [Laravel Authentication](https://laravel.com/docs/5.6/authentication)
### Use a Package Vulnerability Scanner
> As modern PHP applications use a wide variety of external dependencies, you need to be
sure that you’re not using any with known vulnerabilities. To do that, ensure that you’re
regularly scanning your source code with a vulnerability scanner.
- [Roave Security Advisories](https://github.com/Roave/SecurityAdvisories)
- [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories)
- [SensioLabs Security Advisories Checker](https://security.sensiolabs.org/)
- [retire.js](https://github.com/retirejs/retire.js/)
- [AuditJS](https://www.npmjs.com/package/auditjs)
### Use Microframeworks Over Monolithic Frameworks
> Microframeworks contain as few services, libraries, and configurations as possible, while
monolithic frameworks contain a vast array of services, libraries, and configurations on
the of-chance that at some stage you will use them. Reduce the possibility of security
defects by using a microframework if at all possible.
- [Zend Expressive](https://docs.zendframework.com/zend-expressive/)
- [Slim](http://www.slimframework.com/)
- [Silex](http://silex.sensiolabs.org/)
- [Lumen](http://lumen.laravel.com/)
- [Fat-Free Framework](http://fatfreeframework.com/)
### Always Perform Context-Aware Content Escaping
> Whether your outputting information in an HTML template, in CSS, or in JavaScript,
avoid exposing your users to CSRF (Cross Site Request Forgery) and XSS (Cross Site
Scripting) attacks by performing context-aware content escaping.
- [Context-specific escaping with zend-escaper](https://framework.zend.com/blog/2017-05-16-zend-escaper.html)
- [Safer PHP output](https://www.inanimatt.com/php-output-escaping.html)
- [Twig escape method](https://twig.symfony.com/doc/2.x/filters/escape.html)
- [How to Escape Output in Templates (Symfony)](https://symfony.com/doc/current/templating/escaping.html)
- [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
### Deprecate Features and Libraries When They’re No Longer Used
> Stay abreast of the packages and language features that you’re using. If a language
feature planned to be deprecated, such as Mcrypt, or a third-party package becomes
abandoned, then start planning to replace it with an alternative.

- [sensiolabs-de/deprecation-detector](https://github.com/sensiolabs-de/deprecation-detector)
- [samsonasik/is-deprecated](https://github.com/samsonasik/IsDeprecated)
- [How to Deprecate PHP Package Without Leaving Anyone Behind](https://www.tomasvotruba.cz/blog/2017/07/03/how-to-deprecate-php-package-without-leaving-anyone-behind/)
### Never Display PHP Errors and Exceptions in Production
> While errors, warnings, and exceptions are helpful during development, if displayed in
production or any other public-facing environment, they may expose sensitive
information or intellectual property. Ensure that this information is logged internally, and
not exposed publicly.

- [PHP Error Reporting](https://secure.php.net/manual/en/function.error-reporting.php)
- [Whoops - PHP errors for cool kids](http://filp.github.io/whoops/)
- [Error Handling in Laravel](https://laravel.com/docs/5.6/errors)
### Disable Unsafe and Unrequired Functionality
> Some PHP installations can be preconfigured with unsafe and unrequired functionality
already enabled. Ensure that you review your PHP configuration and `phpinfo()` output
for any unsafe settings and disable or limit them.
- [OWASP PHP Configuration Cheat Sheet](https://www.owasp.org/index.php/PHP_Configuration_Cheat_Sheet)
### Filter File Uploads
> If malicious files can be uploaded and executed by users, then the application, its data, or
the supporting server(s) can be compromised. Ensure that PHP’s file upload
configuration is correctly configured to avoid these attacks from occurring.
- [OWASP Unrestricted File Upload](https://www.owasp.org/index.php/Unrestricted_File_Upload)
- [How to securely upload files with PHP](https://php.earth/docs/security/uploading)
- [How to Securely Allow Users to Upload Files](https://paragonie.com/blog/2015/10/how-securely-allow-users-upload-files)
### Disable or Limit Program Execution Functionality
> Program execution functionality, such as exec, passthru, shell_exec, and system, can leave
open the possibility for users to be able to execute arbitrary code on your system and
shell injection attacks. Disable this functionality if it’s not explicitly needed.
- [Program execution Functions](https://secure.php.net/manual/en/ref.exec.php)
- [Shell injection attacks](https://www.owasp.org/index.php/PHP_Security_Cheat_Sheet#Shell_Injection)
- [PHP disable_functions](http://php.net/manual/en/ini.core.php#ini.disable-functions)

# INFRASTRUCTURE
### Connect to Remote Services With TLS or Public Keys
> When accessing any database, server, or remote services, such as _Redis_, _Beanstalkd_,
or _Memcached_, always do so using TLS or public keys. Doing so ensures that only
authenticated access is allowed and that requests and responses are encrypted, and data
is not transmitted in the clear.
- [Public Key Infrastructure and SSL/TLS Encryption](https://www.digitalocean.com/community/tutorials/7-security-measures-to-protect-your-servers#public-key-infrastructure-and-ssltls-encryption)
- [What is SSL, TLS and HTTPS?](https://www.websecurity.symantec.com/security-topics/what-is-ssl-tls-https)
- [SSL vs. TLS - What’s the Diference?](https://www.globalsign.com/en/blog/ssl-vs-tls-difference/)
### Check Your SSL / TLS Configurations
> Ensure that your server’s SSL/TLS configuration is up to date and correctly configured,
and isn’t using weak ciphers, outdated versions of TLS, valid security certificates without
weak keys, etc, by scanning it regularly.
- [SSL Labs](https://www.ssllabs.com/)
- [Observatory by Mozilla](https://observatory.mozilla.org/)
### Renew Your Certificates On Time
> Using SSL certificates is essential to encrypting your web site or application’s trafc with
HTTPS. However, they do expire. Ensure that you’re updating your certificates before
they expire.
- [Get Alerts For Expiring SSL Certificates](https://serverlesscode.com/post/ssl-expiration-alerts-with-lambda/)
- [Free and Auto-Renewing SSL Certificates: Letsencrypt Quick Setup (2017 Edition)](https://www.imagescape.com/blog/2017/11/27/free-and-auto-renewing-ssl-certificates-letsencrypt-quick-setup-2017-edition/)
### Rate Limit Requests to Prevent DDoS Attacks
> To stop users attempting to perform brute force login attacks and overwhelm your forms,
use tools such as Fail2Ban to throttle requests to acceptable levels.

- [Fail2ban]()
- [How To Protect SSH with Fail2Ban on Ubuntu 14.04](https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-ubuntu-14-04)
### Log All The Things
> Regardless of whether you’re logging failed login attempts, password resets, or debugging
information, make sure that you’re logging, and with an easy to use, and mature package,
such as Monolog.

- [Monolog](https://github.com/Seldaek/monolog)
- [PHP Logging Basics](https://www.loggly.com/ultimate-guide/php-logging-basics/)
### Do not send sensitive information in headers
> By default PHP will set his version number in the HTTP headers. Some frameworks may
do the same as well.

- [Hide PHP and Apache informations from HTTP headers](https://tecadmin.net/basic-security-tips-hide-apachephp-information/)
### Do Not Store Sensitive Data In Configuration Files
> Just like you shouldn’t store sensitive data in cache entries, you also should not store
sensitive data in configuration files. This includes ssh keys, access credentials, and API
tokens. Store them in environment variables instead.
- [The Twelve-Factor App](https://12factor.net/)
- [PHP dotenv](https://github.com/vlucas/phpdotenv)
### Make Requests Over HTTPS Wherever Possible
> To avoid Man in the Middle attacks, to protect the integrity of your site, and privacy of
your users, you need to make all requests over HTTPS—especially requests involving
sensitive data, such as logins, password and account changes.
- [Why HTTPS Matters](https://developers.google.com/web/fundamentals/security/encrypt-in-transit/why-https)
- [Let’s Encrypt](https://letsencrypt.org/)
- [Apache SSL/TLS Strong Encryption: How-To](https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html)
- [Configuring NGINX HTTPS servers](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [Docker, Traefik, and Let’s Encrypt](https://docs.traefik.io/user-guide/docker-and-lets-encrypt/)
# PROTECTION
### Send All Available Security Headers
> There are several security headers that you can use to make your websites and web-based
applications more secure, for minimal efort. These include HSTS, X-XSS-Protection, XFrame-Options, X-Content-Type-Options, and a Content Security Policy. Ensure that
they’re being configured correctly and sent in your request responses.

- [Use these Five Security Headers To Create More Secure Applications](https://matthewsetter.com/five-security-headers/)
- [SecurityHeaders](https://securityheaders.com/)
- [PHP header function](https://secure.php.net/manual/en/function.header.php)
- [Hardening Your HTTP Security Headers](https://www.keycdn.com/blog/http-security-headers/)
### Have a Content Security Policy
> Whether you have a one page, static website, a large static website, or a sophisticated
web-based application, implement a Content Security Policy (CSP). It helps to mitigate a
range of common attack vectors, such as XSS.

- [Content Security Policy (CSP) via MDN web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Content Security Policy (CSP) via the Google Chrome extensions documentation](https://developer.chrome.com/extensions/contentSecurityPolicy)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Content Security Policy (CSP) Validator](https://cspvalidator.org/#url=https://cspvalidator.org/)
- [Easily add a CSP with Sqreen](https://www.sqreen.io/)
### Protect your users against account takeovers
> Credential stufng or brute force attacks are easy to setup. You should make sure your
users are protected against account takeovers.
- [Sqreen](https://www.sqreen.io/)
- [Blocking Bruteforce attacks - OWASP](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks)
### Monitor your application security
> Monitor your application security for suspicious behaviors and attacks. Knowing when
your application is starting to get attacked is key to protect it before it's too late.
- [Monitor your PHP App security](https://www.sqreen.io/?utm_medium=social-owned&utm_source=whitepaper&utm_campaign=Whitepaper%20-%20PHP%20Security%20Checklist)
### Protect your sensitive data in real-time
> Code vulnerabilities will always exist. Make sure you have a security solution in place that
detects and blocks OWASP attacks but also business logic threats.
- [Protect your PHP app ](https://www.sqreen.io/?utm_medium=social-owned&utm_source=whitepaper&utm_campaign=Whitepaper%20-%20PHP%20Security%20Checklist)
