#
#   OpenLDAP pwdPolicy/shadowAccount Overlay
#   Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
#   All rights reserved.
#
#   Dominus vobiscum. Et cum spiritu tuo.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted only as authorized by the OpenLDAP
#   Public License.
#
#   A copy of this license is available in the file LICENSE in the
#   top-level directory of the distribution or, alternatively, at
#   <http://www.OpenLDAP.org/license.html>.
#

LDAPCONF="$(cd "$(dirname "${_}")" && pwd)/ldap.conf"
echo $TEST_ENV_PROFILE_DIR

test_env_debug()
{
   /tmp/slapo-pwdshadow/libexec/slapd \
      -d conns,filter,config,acl,stats,sync \
      -f /tmp/slapo-pwdshadow/etc/openldap/slapd.conf \
      -h "ldap://localhost ldapi://%2Ftmp%2Fslapo-pwdshadow%2Fvar%2Frun%2Fslapd.sock" \
      "${@}"
}

# end of profile
