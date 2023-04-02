

OpenLDAP pwdPolicy/shadowAccount Overlay
========================================

Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted only as authorized by the OpenLDAP
Public License.

A copy of this license is available in the file LICENSE in the
top-level directory of the distribution or, alternatively, at
<http://www.OpenLDAP.org/license.html>.


Contents
--------

   * Overview
   * Software Requirements
   * Source Code
   * Package Maintence Notes


Overview
==========

This package contains an overlay for the OpenLDAP slapd which generates
substitute attribtues for accountShadow which are derived from  the password
policies used by the slapo-ppolicy overlay. This package defines an alternate
schema which is a drop in replacement for the accountShadow and related
attributes which are defined by RFC2307.


Software Requirements
=====================


Source Code
===========

The source code for this project is maintained using git
(http://git-scm.com).  The following contains information to checkout the
source code from the git repository.

Browse Source:

   * https://github.com/syzdek/slapo-pwdshadow

Git URLs:

   * https://github.com/syzdek/slapo-pwdshadow.git
   * https://github.com/bindle/ldap-utils.xcodeproj.git

Downloading Source:

      $ git clone https://github.com/syzdek/slapo-pwdshadow.git

Preparing Source:

      $ cd slapo-pwdshadow
      $ ./autogen.sh

Compiling Source:

      $ cd build
      $ ./configure
      $ make && make install

For more information on building and installing using configure, please
read the INSTALL file.

Git Branches:

   * master - Current release of packages.
   * next   - changes staged for next release
   * pu     - proposed updates for next release
   * xx/yy+ - branch for testing new changes before merging to 'pu' branch


Package Maintence Notes
=======================

This is a collection of notes for developers to use when maintaining this
package.

New Release Checklist:

   - Switch to 'master' branch in Git repository.
   - Update version in configure.ac.
   - Update date and version in ChangeLog.
   - Commit configure.ac and ChangeLog changes to repository.
   - Create tag in git repository:

           $ git tag -s v${MAJOR}.${MINOR}

   - Push repository to publishing server:

           $ git push --tags origin master:master next:next pu:pu

Creating Source Distribution Archives:

      $ ./configure
      $ make update
      $ make distcheck
      $ make dist-bzip2
      $ make dist-xz


