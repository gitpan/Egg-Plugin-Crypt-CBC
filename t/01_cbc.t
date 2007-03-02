package EggTest;
use strict;
use Test::More tests => 9;
use base qw/Egg::Plugin::Crypt::CBC/;
use Class::C3;

my %config= (
  plugin_crypt_cbc=> {
    cipher=> 'Blowfish',
    key   => '(abcdef)',
    },
  );
my $e= bless {}, __PACKAGE__;

__PACKAGE__->setup($e);

my $plain_text= 'secret text';

ok( my $cbc= $e->cbc );
ok( my $secret= $cbc->encrypt($plain_text) );
ok( $secret ne $plain_text );
ok( my $decrypt= $cbc->decrypt($secret) );
ok( $plain_text eq $decrypt );
ok( $secret= $e->cbc_encode($plain_text) );
ok( $secret ne $plain_text );
ok( $decrypt= $e->cbc_decode($secret) );
ok( $plain_text eq $decrypt );

sub config { \%config }
sub setup  { \%config }
