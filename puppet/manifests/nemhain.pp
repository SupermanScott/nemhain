node default {
  exec { "apt-update":
    command => "/usr/bin/apt-get update"
  }

  Exec["apt-update"] -> package {
    "make":
      ensure => installed;
    "libtool":
      ensure => installed;
    "autoconf":
      ensure => installed;
    "automake":
      ensure => installed;
    "gettext":
      ensure => installed;
    "exuberant-ctags":
      ensure => installed;
    "gcc-4.7-base":
      ensure => installed;
    "valgrind":
      ensure => installed;
    "gdb":
      ensure => installed;
    "ragel":
      ensure => installed;
    "pkg-config":
      ensure => installed;
    "libev4":
      ensure => installed;
    "sendip":
      ensure => installed;
  }
}
