=== OOSOFT WAF Security ===
Contributors: oosofttech
Donate link: https://oosoft.co.in
Tags: security, firewall, waf, malware, brute-force
Requires at least: 5.9
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A production-ready WordPress application-level Web Application Firewall (WAF) with request filtering, upload malware protection, and security logging.

== Description ==

OOSOFT WAF Security is a comprehensive WordPress security plugin that acts as an application-level Web Application Firewall. It protects your site in real-time by filtering malicious requests, scanning uploads for malware, and maintaining detailed security logs.

= Free Features =

**Request Firewall**

* SQL injection pattern detection and blocking
* Cross-site scripting (XSS) pattern detection and blocking
* Dangerous user-agent blocking (scanners, exploit tools)
* XML-RPC endpoint protection
* Brute-force login rate limiting

**Upload Malware Protection**

* Block uploads with dangerous file extensions (PHP, ASP, shell scripts, etc.)
* Detect and block double-extension attacks (e.g., file.jpg.php)
* Basic malware signature scanning of file contents
* Admin email notification on blocked uploads
* Full audit trail for upload attempts

**Security Logging**

* Detailed log of every blocked attack
* Detailed log of every blocked upload attempt
* IP address, user agent, request URI, and attack payload recorded
* Configurable log retention period
* Dashboard view of recent security events

= Pro Features (Coming Soon) =

* Imunify360 integration for advanced scanning
* Auto-detect scanning engine (built-in, Imunify360, or automatic)
* Quarantine suspicious uploads
* Temporary automatic IP bans
* Custom malware signature rules

= About OOSOFT Technology =

OOSOFT Technology specialises in WordPress security solutions. Visit [https://oosoft.co.in](https://oosoft.co.in) to learn more.

== Installation ==

1. Upload the `oosoft-waf-security` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **WAF Security** in the WordPress admin menu to configure your settings.
4. Review the dashboard to confirm all protection modules are active.

== Frequently Asked Questions ==

= Will this plugin slow down my site? =

No. The WAF runs lightweight pattern matching on incoming requests. The performance overhead is negligible on any modern server.

= Will XML-RPC protection break the WordPress mobile app? =

Yes. If you use the official WordPress mobile app or services that rely on XML-RPC (such as Jetpack), leave XML-RPC protection disabled. Only enable it if you do not use any XML-RPC-dependent services.

= Can I whitelist my own IP address? =

IP whitelisting is planned for a future release. Currently, all requests are subject to the same firewall rules.

= What file extensions are blocked by the upload scanner? =

The scanner blocks server-executable extensions including PHP variants (php, php3, php4, php5, php7, php8, phtml, pht, phar), ASP variants, shell scripts (sh, bash, csh), CGI scripts (cgi, pl, py, rb), and compiled executables (exe, dll, bat, cmd). Standard image, document, and media files are unaffected.

= How do I report a security vulnerability in this plugin? =

Please report security issues responsibly by emailing the author via https://oosoft.co.in. Do not open a public issue.

= Is this plugin compatible with multisite? =

Single-site operation is fully supported. Multisite compatibility is planned for a future release.

== Screenshots ==

1. Dashboard overview showing real-time protection status and attack statistics.
2. Settings page with firewall, upload scanner, and logging configuration.
3. Security logs table with detailed attack information.

== Changelog ==

= 1.0.0 =
* Initial release.
* Request firewall with SQL injection, XSS, and bad user-agent blocking.
* XML-RPC protection toggle.
* Brute-force login rate limiting.
* Upload malware scanner with extension and signature checks.
* Security logging with configurable retention.
* Admin dashboard with attack statistics.
* Pro feature architecture (gated, not yet activated).

== Upgrade Notice ==

= 1.0.0 =
Initial release. No upgrade action required.
