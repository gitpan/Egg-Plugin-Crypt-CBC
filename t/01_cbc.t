
use Test::More tests => 9;
use Egg::Helper::VirtualTest;

my $t= Egg::Helper::VirtualTest->new( prepare=> {
  controller => { egg_includes => [qw/ Crypt::CBC /] },
  config => { plugin_crypt_cbc=> {
    cipher => 'Blowfish',
    key    => '(abcdef)',
    } },
  });

my $e= $t->egg_pcomp_context;

my $plain_text= 'secret text';

ok my $cbc= $e->cbc;
ok my $secret= $cbc->encrypt($plain_text);
ok $secret ne $plain_text;
ok my $decrypt= $cbc->decrypt($secret);
ok $plain_text eq $decrypt;
ok $secret= $e->cbc->encode($plain_text);
ok $secret ne $plain_text;
ok $decrypt= $e->cbc->decode($secret);
ok $plain_text eq $decrypt;
