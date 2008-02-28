use Module::Build;

my $builder = Module::Build->new(

  module_name       => 'Egg::Plugin::Crypt::CBC',
  dist_version_from => 'lib/Egg/Plugin/Crypt/CBC.pm',
  dist_abstract     => 'lib/Egg/Plugin/Crypt/CBC.pm',
  dist_author       => 'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>',
  license           => 'perl',

  requires => {

    'Egg::Release'    => 2.00,
    'Crypt::CBC'      => 2.22,
    'Crypt::Blowfish' => 2.10,
    'Crypt::DES'      => 2.05,
    'Crypt::Camellia' => 2.01,
    'Crypt::Rabbit'   => 1.00,
    'Crypt::Twofish2' => 1.01,

    'Test::More'           => 0,
    'Test::Pod'            => 0,
    'Test::Perl::Critic'   => 0,
    'Test::Pod::Coverage'  => 0,
    },

  );

$builder->create_build_script();
