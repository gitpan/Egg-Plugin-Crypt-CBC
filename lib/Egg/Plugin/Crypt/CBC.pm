package Egg::Plugin::Crypt::CBC;
#
# Copyright (C) 2006 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: CBC.pm 274 2007-03-02 14:21:10Z lushe $
#
use strict;
use MIME::Base64;
use Crypt::CBC;

our $VERSION = '0.03';

sub setup {
	my($e)= @_;
	my $config= $e->config->{plugin_crypt_cbc}
	 || Egg::Error->throw(q/Please setup 'plugin_crypt_cbc'./);
	$config->{cipher}
	 || Egg::Error->throw(q/Please setup 'plugin_crypt_cbc->{cipher}'./);
	$config->{key}
	 || Egg::Error->throw(q/Please setup 'plugin_crypt_cbc->{key}'./);
	$config->{iv}      ||= '$KJh#(}q';
	$config->{padding} ||= 'standard';
	$config->{prepend_iv}= 0 unless exists($config->{prepend_iv});
	$config->{regenerate_key}= 1 unless exists($config->{regenerate_key});
	$e->next::method;
}
sub cbc {
	$_[0]->{cbc} ||= do {
		my $e= shift;
		my %options= %{$e->config->{plugin_crypt_cbc}};
		if (@_) {
			my $opt= ref($_[0]) ? $_[0]: {@_};
			@options{keys %$opt}= values %$opt;
		}
		Crypt::CBC->new(\%options);
	  };
}
sub cbc_encode {
	my $e    = shift;
	my $plain= shift || return "";
	my $cbc  = shift || $e->cbc;
	my $crypt= encode_base64($cbc->encrypt($plain));
	$crypt=~tr/\r\n\t//d;
	$crypt || "";
}
sub cbc_decode {
	my $e    = shift;
	my $crypt= shift || return "";
	my $cbc  = shift || $e->cbc;
	$cbc->decrypt(decode_base64($crypt)) || "";
}
sub reset_cbc {
	undef($_[0]->{cbc});
	$_[0]->cbc;
}

1;

__END__

=head1 NAME

Egg::Plugin::Crypt::CBC - The encryption is supported.

=head1 SYNOPSIS

  package [MYPROJECT];
  use strict;
  use Egg qw/Crypt::CBC/;

Configuration is setup.

  plugin_crypt_cbc=> {
    cipher=> 'Blowfish',
    key   => 'uniqueid',
    ...
    },

* The setting is an option to pass to L<Crypt::CBC>.

Example of code.

  my $plain= 'secret text';
  
  my $secret= $e->cbc_encode( $plain );
  
  print $e->cbc_decode( $secret ); # decrypts it.

=head1 DESCRIPTION

It is necessary to install the module corresponding to the code form
 specified for 'B<cipher>' beforehand.

For instance, please specify it by installing the following modules.

L<Crypt::Blowfish>,
L<Crypt::DES>,
L<Crypt::IDEA>,
L<Crypt::RSA>,
etc...

This module is wrapper of L<Crypt::CBC>.
Please see the manual of L<Crypt::CBC> in detail.

=head1 METHODS

=head2 $e->cbc([OPTION]);

Crypt::CBC object is returned.

When the option is passed, the default value of the setting is overwrited.

=head2 $e->cbc_encode([PLAIN_TEXT], [CBC_OBJECT]);

[PLAIN_TEXT] is encrypted.

When [PLAIN_TEXT] is omitted, $e->cbc is used. 

=head2 $e->cbc_decode([CIPHERTEXT], [CBC_OBJECT]);

[CIPHERTEXT] is decrypted.

When [CIPHERTEXT] is omitted, $e->cbc is used. 

=head1 SEE ALSO

L<Crypt::CBC>,
L<Crypt::DES>,
L<Crypt::IDEA>,
L<Crypt::RSA>,
L<Crypt::Blowfish>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2006 by Bee Flag, Corp. E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

