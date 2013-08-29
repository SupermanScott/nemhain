node default {
  package {
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
  }
}
