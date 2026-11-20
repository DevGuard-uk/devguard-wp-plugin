=== DevGuard ===
Contributors: devguard
Tags: security, protection, licensing, invoice lock, domain lock, maintenance
Requires at least: 5.6
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Protect client websites with remote project locking, invoice milestone autolock enforcement, and domain allowlisting.

== Description ==

DevGuard Website Protection provides agencies, freelance web developers, and contractors with automated protection for client websites.

* **Remote Project Lock**: Lock delinquent or unauthorized deployments instantly from the DevGuard Portal.
* **Domain Lock**: Restrict website execution to authorized hostnames and wildcards (`*.client-site.com`), preventing unauthorized staging clones and domain scraping.
* **SEO-Safe HTTP 503**: Visitors to locked sites receive standard HTTP 503 Service Unavailable responses with `Retry-After` headers and `noindex` directives, ensuring search engine rankings are preserved.
* **Administrator Bypass Guarantee**: Logged-in WordPress administrators are never locked out of WordPress. An admin notice banner alerts them that public visitors are seeing the lock page.
* **Fail-Safe Open**: Network timeouts or API outages will never break client sites.
* **Zero Bloat**: Lightweight PHP implementation with zero external dependencies.

== Installation ==

1. Upload the `devguard` folder to the `/wp-content/plugins/` directory, or install the `.zip` file via WordPress Admin > Plugins > Add New > Upload Plugin.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Settings > DevGuard** and enter your Project ID.
4. Save changes.

== Frequently Asked Questions ==

= Will I be locked out if the site is locked? =
No. Logged-in administrators with `manage_options` capability always have bypass access and will see a warning notice instead.

= What happens if the DevGuard API is unreachable? =
By default, the plugin operates in `failSafe: open` mode, granting access so visitor traffic is never blocked.
