use Module::Build;

my $builder = Module::Build->new(

  module_name       => 'Egg::Plugin::Crypt::CBC',
  dist_version_from => 'lib/Egg/Plugin/Crypt/CBC.pm',
  dist_author       => 'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>',
  license           => 'perl',

  requires => {
    'Egg::Release'    => 1.13,
    'Crypt::CBC'      => 0,
    'Crypt::Blowfish' => 0,
    'Test::More'      => 0,
    'Test::Pod'       => 0,
    },

  );

$builder->create_build_script();
