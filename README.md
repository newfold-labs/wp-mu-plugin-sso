# WordPress SSO MU Plugin

This is a public repo for the sso.php file that Bluehost uses in the control panel to log into WP.

## Deployments

To deploy updated versions of this plugin:

- Update the code in `master` on this repo and bump the version number.
- Push the contents of the `sso.php` file to this [Bitbucket repo](https://bitbucket.org/newfold/gap/src/master/lib/GT/WP/mu-plugins/sso.php).
- When a user clicks "Login to WordPress" from the Bluehost dashboard, the MU plugin will be auto-updated to the latest version (or added if it was deleted).
