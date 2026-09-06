PLUGIN_NAME= adguardhome-ha
PLUGIN_VERSION= 1.0
PLUGIN_DEPENDS= adguardhome
PLUGIN_CONFLICTS= adguardhome-maxit adguardhome
PLUGIN_COMMENT= AdGuard Home with authenticated state-sync replication
PLUGIN_MAINTAINER= N/A
PLUGIN_WWW= https://github.com/Hintay/opnsense-adguardhome-ha
PLUGIN_LICENSE= BSD2CLAUSE

.include "../../Mk/plugins.mk"
