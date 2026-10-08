# WordPress SSO MU Plugin

This is a public repo for the sso.php file that Bluehost uses in the control panel to log into WP.

It covers everything [wp-module-sso](https://github.com/newfold-labs/wp-module-sso) does, so a site does not need the module for SSO. When the module is also active, the module's REST route, WP-CLI command, and login screen output are used instead of this file's copies.

## Deployments

To deploy updated versions of this plugin:

- Update the code in `master` on this repo and bump the version number.
- Push the contents of the `sso.php` file to this [Bitbucket repo](https://bitbucket.org/newfold/gap/src/master/lib/GT/WP/mu-plugins/sso.php).
- When a user clicks "Login to WordPress" from the Bluehost dashboard, the MU plugin will be auto-updated to the latest version (or added if it was deleted).

## Features

### Legacy login: `admin-ajax.php?action=sso-check&nonce=…&salt=…`

Used by the control panel and `wp newfold sso`. `sha256( nonce . salt )` must match the `sso_token` transient (or option). The token is single use. A nonce ending in `-e<unix time>` expires after 5 minutes.

`user` can be a user ID or email. Without it, the first administrator is used. If `user` is given but does not match anyone, the login fails.

This flow runs on `muplugins_loaded`, before regular plugins load. Hooks and filters it fires (see below) only reach other must-use plugins.

### Token login: `admin-ajax.php?action=newfold_sso_login&token=…`

Used by Hiive. The token comes from the REST endpoint, is stored in the `newfold_sso_token` user meta, is valid for 10 minutes, and is single use. This flow runs on the normal admin-ajax hook, so brand plugins can filter it.

### REST endpoint: `GET /wp-json/newfold-sso/v1/sso`

Returns a token login URL for the current user. Requires the `read` capability.

### WP-CLI: `wp newfold sso`

Prints a legacy login link. Options: `--id`, `--email`, `--username`, `--role`, `--min=<minutes>` (default 3), `--url-only`.

### Shared behavior

- Destination: `bounce` or `redirect` (a path inside `wp-admin`). Other query parameters are carried over. Off-site URLs are rejected.
- After 5 failures in 5 minutes from one IP address, logins are blocked.
- Usernames containing `' " \ < |` are rejected and `wp-login.php?error=invalid_username` shows a message.
- Redirect guard: other plugins cannot replace the SSO destination during the login request or the next admin request.
- "Login with <Host>" button on `wp-login.php` when a brand plugin sets the `newfold/sso/hosting_login` filter.

### Hooks

| Hook | Type | Notes |
| --- | --- | --- |
| `newfold_sso_success` | action | `( WP_User $user, string $redirect )` |
| `newfold_sso_fail` | action | After a failed attempt |
| `eig_sso_success`, `eig_sso_fail` | action | Legacy names, fired only when something listens |
| `newfold_sso_success_url_default` | filter | Destination when no `bounce`/`redirect` is given |
| `newfold_sso_success_url` | filter | Final destination |
| `eig_sso_redirect` | filter | Legacy name for the above |
| `newfold_sso_redirect_guard_ttl` | filter | Seconds the redirect guard lasts (default 120, minimum 30) |
| `newfold/sso/hosting_login` | filter | `enabled`, `url`, `label`, `icon_svg`, `new_tab`, `accent_color` |

## Debugging

`sso.php` is replaced on every control-panel login, so log statements added to this file disappear on the next SSO. Put a separate must-use plugin on the site (any file other than `sso.php`) and listen for `newfold_sso_debug`. It has to be a must-use plugin because the legacy flow runs before regular plugins load.

The hook receives an event name and a context array. The context never includes the nonce, salt, or token.

```php
<?php
/**
 * Plugin Name: SSO debug log
 */

add_action( 'newfold_sso_debug', function ( $event, $context ) {
	error_log( 'sso ' . $event . ' ' . wp_json_encode( $context ) );
}, 10, 2 );
```

Most login events include `flow`, which is `legacy` (`sso-check`) or `token` (`newfold_sso_login`).

| Event | When it fires |
| --- | --- |
| `early_start` | `sso-check` is handled on `muplugins_loaded`, before regular plugins load |
| `check_start` | A login attempt started. Legacy context has `has_nonce`, `has_salt`, `has_user`, `has_bounce`. Token context has `has_token`, `has_bounce` |
| `missing_credentials` | Nonce and salt, or token, were not in the request |
| `blocked` | Too many recent failures. Context has `attempts` |
| `token_invalid` | Token missing, expired, or not a match. Legacy context has `expired`, `token_found`, `from_option`. Token context has `reason` (`malformed`, `user_not_found`, `expired`, `mismatch`) |
| `user_not_found` | Legacy token matched but the user could not be loaded |
| `invalid_username` | The username has characters SSO rejects. Context has `user_id` |
| `success` | Login succeeded. Context has `user_id`, `redirect`, and `from_option` for legacy |
| `link_created` | The REST endpoint or WP-CLI issued a link. Context has `source` (`rest` or `cli`), `user_id`, `expires_in` |
| `redirect_hijacked` | Another plugin's redirect was rewritten to the SSO destination. Context has `from` and `to` |
| `landing_guard` | The next admin request re-pinned the SSO destination |
| `landing_guard_invalid` | The stored landing URL was discarded |
| `landing_guard_finished` | Landing guard ended. Context `kept` is true when a hijack was rewritten and the guard stays for the next request |
