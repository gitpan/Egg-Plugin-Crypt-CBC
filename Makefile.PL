use inc::Module::Install;

name         'Egg-Plugin-Crypt-CBC';
author       'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>';
all_from     'lib/Egg/Plugin/Crypt/CBC.pm';
version_from 'lib/Egg/Plugin/Crypt/CBC.pm';
license      'perl';

requires 'Egg::Release'    => 2.00;
requires 'Crypt::CBC'      => 2.22;
requires 'Crypt::Blowfish' => 2.10;

build_requires 'Test::More';
build_requires 'Test::Pod';
build_requires 'Test::Perl::Critic';
build_requires 'Test::Pod::Coverage';

use_test_base;
auto_include;
WriteAll;
