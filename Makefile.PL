use inc::Module::Install;

name         'Egg-Plugin-Crypt-CBC';
author       'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>';
all_from     'lib/Egg/Plugin/Crypt/CBC.pm';
version_from 'lib/Egg/Plugin/Crypt/CBC.pm';
license      'perl';

requires 'Egg::Release' => 1.13;
requires 'Crypt::CBC';
requires 'Crypt::Blowfish';

build_requires 'Test::More';
build_requires 'Test::Pod';

use_test_base;
auto_include;
WriteAll;
