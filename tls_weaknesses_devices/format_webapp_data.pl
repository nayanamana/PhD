#!/usr/bin/perl

#Extract data from Censys Data in GoogleCloud: https://bigquery.cloud.google.com/dataset/censys-io:domain_public to be used
#as an input to this script (in intermediary format)
#
#Example SQL query to extract the input:
#SELECT
#  alexa_rank,
#  domain,
#  TO_JSON_STRING(p443.https_www.tls.certificate.parsed.subject.country) arr,
#  p443.https.tls.version,
#  p443.https.tls.cipher_suite.name as cipher_suite_name,
#  p443.https.tls.certificate.parsed.issuer_dn,
#  p443.https.tls.certificate.parsed.subject_dn,
#  p443.https.tls.certificate.parsed.validity.start,
#  p443.https.tls.certificate.parsed.validity.end,
#  p443.https.tls.certificate.parsed.signature.self_signed,
#  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
#  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name as key_algorithm_name,
#  p443.https.tls.certificate.parsed.signature.signature_algorithm.name as signature_algorithm_name,
#  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca as is_ca,
#  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
#  p443.https.tls.server_key_exchange.rsa_params.modulus,
#  p443.https.tls.signature.hash_algorithm,
#  p443.https.tls.validation.browser_trusted,
#  p443.https.dhe.dh_params.prime.value as dhe_prime_value,
#  p443.https.dhe.dh_params.generator.value as dhe_generator_value,
#  p443.https.tls.server_key_exchange.dh_params.prime.value as dh_prime_value,
#  p443.https.tls.server_key_exchange.dh_params.generator.value as dh_generator_value,
#  p443.https.tls.certificate.parsed.fingerprint_sha256
#FROM
#  `censys-io.domain_public.20180506`
#WHERE
#  alexa_rank IS NOT NULL AND alexa_rank < 1000001
#GROUP BY
#  alexa_rank,
#  domain,
#  arr,
#  p443.https.tls.version,
#  p443.https.tls.cipher_suite.name,
#  p443.https.tls.certificate.parsed.issuer_dn,
#  p443.https.tls.certificate.parsed.subject_dn,
#  p443.https.tls.certificate.parsed.validity.start,
#  p443.https.tls.certificate.parsed.validity.end,
#  p443.https.tls.certificate.parsed.signature.self_signed,
#  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
#  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name,
#  p443.https.tls.certificate.parsed.signature.signature_algorithm.name,
#  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca,
#  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
#  p443.https.tls.server_key_exchange.rsa_params.modulus,
#  p443.https.tls.signature.hash_algorithm,
#  p443.https.tls.validation.browser_trusted,
#  p443.https.dhe.dh_params.prime.value,
#  p443.https.dhe.dh_params.generator.value,
#  p443.https.tls.server_key_exchange.dh_params.prime.value,
#  p443.https.tls.server_key_exchange.dh_params.generator.value,
#  p443.https.tls.certificate.parsed.fingerprint_sha256,
#  p443.https_www.tls.certificate.parsed.extensions.basic_constraints.is_ca


use Data::Dumper;

use strict;
use warnings;

$|=1;

use Encode qw(encode decode);


use Getopt::Long;
use Tree::Simple;
use Tree::Parser;
use Date::Manip;

use File::Sip;
use File::Basename;

use JSON;

my $file;
my $dest;


GetOptions ("file=s" =>\$file,
            "destination=s" =>\$dest) or die ("Error in command line arguements\n");

unless ($file && (-e $file) && -d dirname($dest)) {
   die "\nNot all options specified:\n\n$0 -d <destination output file> -f <input data file>\n\nExample:\n$0 -d '/home/naya/fc_ext/scripts/data/090518/alexa_domains' -f '/home/naya/fc_ext/scripts/data/090518/alexa_domains_090518-2-000000000000'\n";
}


#Extract the CN of a certficate given DN
sub find_cert_cn {
   my $cert_dn  = shift;

   return '' unless $cert_dn;
   my @cert_dn_tokens = split ',', $cert_dn;
   foreach my $t (@cert_dn_tokens) {
      $t =~ s/^\s+|\s+$//g;
      my @items = split '=' , $t;
      return $items[1] if (scalar @items > 1 and $items[0] eq 'CN' && $items[1]);
   }

   return '';

}

#Extract the Country of a certificate given DN
sub find_cert_country {
   my $cert_dn  = shift;

   return '' unless $cert_dn;
   my @cert_dn_tokens = split ',', $cert_dn;
   foreach my $t (@cert_dn_tokens) {
      $t =~ s/^\s+|\s+$//g;
      my @items = split '=' , $t;
      return $items[1] if (scalar @items > 1 and $items[0] eq 'C' && $items[1]);
   }

    return '';

}

#Replace null values with an empty string
sub handle_null {
   my $d = shift;
   $d =~ s/	//g if ($d);
   return $d ? $d : '';
}

#Process the input file
sub process_file {
   open(F, $file) or die "OPENING $file: $!\n";

   my $header = "country	tls_version	cipher_suite_name	key_ex_auth_alg	key_en_alg	hash_alg	subject_dn	issuer_dn	subject_org	issuer_org	validity_start	validity_end	validity_period	days_to_expire	self_signed	key_length	key_algorithm_name	signature_algorithm_name	is_ca	browser_trusted	dh_prime_val	dh_gen_val	sha256_fp	domain\n";
   write_line($header);  


   while(<F>) {
     my $line = $_;
     my $s = from_json($line);
     my $time_now = localtime();

     my $cipher_suite = $s->{cipher_suite_name};
     my $alexa_rank = $s->{alexa_rank};
     my $tls_version = $s->{version};
     my $country = "";
     if ($s->{arr} && $s->{arr} =~ /(\w+)/) {
          $country = $1;
     }
     my $subject_dn = $s->{subject_dn};
     my $issuer_dn = $s->{issuer_dn};
     my $validity_start = $s->{start};
     my $validity_end = $s->{end};
     my $self_signed = $s->{self_signed}  && $s->{self_signed} =~ /1/ ? 1 : (defined($s->{self_signed}) && $s->{self_signed} =~ /0/ ? 0 : undef);
     my $rsa_key_length = $s->{length};
     my $key_alg_name = $s->{key_algorithm_name};
     my $sig_alg_name = $s->{signature_algorithm_name};
     my $is_ca = $s->{is_ca}  && $s->{is_ca} =~ /true/ ? 1 : (defined($s->{is_ca}) && $s->{is_ca} =~ /false/ ? 0 : "");
     my $browser_trusted = $s->{browser_trusted}  && $s->{browser_trusted} =~ /true/ ? 1 : (defined($s->{browser_trusted}) && $s->{browser_trusted} =~ /false/ ? 0 : "");
     my $dh_params_prime_value = $s->{dh_prime_value};
     my $dh_params_generator_value = $s->{dh_generator_value};
     my $fingerprint_sha256 = $s->{fingerprint_sha256};
     my $domain = $s->{domain};

     my ($key_ex_auth_alg, $key_en_alg, $hash_alg) = ('', '' , '');

     if ($cipher_suite && $cipher_suite =~ /^.+?_(.+?)_WITH_(.+)_(.+?)$/ ) {
             $key_ex_auth_alg = $1 ? $1 : "";
             $key_en_alg = $2 ? $2 : "";
             $hash_alg = $3 ? $3 : "";
     }

    my ($sub_o, $iss_o) = ('', '');

    if ($subject_dn && $subject_dn =~ /,\s*?O=(.+?)\,\s*?/) {
           $sub_o = $1;

     }

     if ($issuer_dn && $issuer_dn =~ /,\s*?O=(.+?)\,\s*?/
) {
           $iss_o = $1;

     }


     my $entry = handle_null($country) . "	" . handle_null($tls_version) . "	" . handle_null($cipher_suite) . "	$key_ex_auth_alg	$key_en_alg	$hash_alg	" . handle_null($subject_dn) . "	" . handle_null($issuer_dn)  . "	" . handle_null($sub_o) ."	" . handle_null($iss_o) . "	" . handle_null($validity_start) . "	" . handle_null($validity_end)	  . "	" . get_cert_validity_period($validity_start, $validity_end) . "	" . get_cert_validity_period($time_now, $validity_end) . "	" . ($self_signed ? 'SELF_SIGNED' : '')  . "	" . handle_null($rsa_key_length)	. "	" . handle_null($key_alg_name) . "	" . handle_null($sig_alg_name) . "	" . handle_null($is_ca) . "	" . handle_null($browser_trusted) . "	" . handle_null($dh_params_prime_value) . "	" . handle_null($dh_params_generator_value) . "	" . handle_null($fingerprint_sha256) . "	" . handle_null($domain);	
    write_line("$entry\n");
    print Dumper $entry;
   }

   close(F);
}

#get certificate validity period (in number of days)
sub get_cert_validity_period {
   my $start_time = shift;
   my $end_time = shift;

   my $days = 0;
   my $delta;

   eval {
      my $s = ParseDate($start_time);
      my $e = ParseDate($end_time);

      my $error;
      $delta = DateCalc($s, $e, \$error);
      return unless $delta;

      my $format = '%hd';
      $days = Delta_Format($delta, 0, $format )/(24) ;
   };

   return int($days);

}

#Return the validity period as number of years (you may change this logic according to the preferred format 
sub format_validity_period {
    my $days = shift;

    my ($y, $m, $d) = (0, 0, 0);

    return '' unless ($days);

    $y = int($days/365);
    $d = $days % 365;

    #return "$y years, $d days";
    #return int($days/12*365); #number of months
    return $y; #number of years

}

#Process certificate
sub process_certificate {
   my $cert = shift;

   my $rdata;

   my $hash_ref =  from_json( $cert, { utf8  => 1 } );

   $rdata->{ip} = $hash_ref->{ip} ? $hash_ref->{ip} : '';
   $rdata->{tls_ver} = $hash_ref->{data}->{tls}->{server_key_exchange}->{signature}->{tls_version}->{name} ? $hash_ref->{data}->{tls}->{server_key_exchange}->{signature}->{tls_version}->{name} : '';
   $rdata->{cipher_suite}->{name} = ($hash_ref->{data}->{tls}->{server_hello}->{cipher_suite}->{name}) ? $hash_ref->{data}->{tls}->{server_hello}->{cipher_suite}->{name} : '';
   if ($rdata->{cipher_suite}->{name} && $rdata->{cipher_suite}->{name} =~ /^.+?_(.+?)_WITH_(.+?)_.+_(.+?)$/ ) {
      $rdata->{cipher_suite}->{key_ex_auth} = $1;
      $rdata->{cipher_suite}->{key_encryption} = $2;
      $rdata->{cipher_suite}->{hash_alg} = $3;
      $rdata->{cipher_suite}->{key_ex_auth} =~ s/_/+/g if ($rdata->{cipher_suite}->{key_ex_auth});
   }
   $rdata->{cipher_suite}->{key_ex_auth} = '' unless $rdata->{cipher_suite}->{key_ex_auth};
   $rdata->{cipher_suite}->{key_encryption} = '' unless $rdata->{cipher_suite}->{key_encryption};
   $rdata->{cipher_suite}->{hash_alg} = '' unless $rdata->{cipher_suite}->{hash_alg};

   $rdata->{key_size} = ($hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{subject_key_info}->{rsa_public_key}->{length} ) ? $hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{subject_key_info}->{rsa_public_key}->{length} : '';


   #validity periods
   my $time_now = localtime();
   my ($start_time, $end_time) = ($hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{validity}->{start}, $hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{validity}->{end});
   $rdata->{key_validity}->{validity_duration} =  format_validity_period(get_cert_validity_period($start_time, $end_time));
   $rdata->{key_validity}->{remaining_validity_duration} = format_validity_period(get_cert_validity_period($time_now, $end_time));

   my $subject_dn = $hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{subject_dn};
   my $issuer_dn = $hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{issuer_dn};
   my $subject_cn = find_cert_cn($subject_dn);
   my $issuer_cn = find_cert_cn($issuer_dn);

   $rdata->{is_self_signed} = ($subject_dn && $issuer_dn && $subject_dn eq $issuer_dn) ? 1 : 0;
   $rdata->{country} = find_cert_country($subject_dn);

   $rdata->{is_ca} = $hash_ref->{data}->{tls}->{server_certificates}->{certificate}->{parsed}->{extensions}->{basic_constraints}->{is_ca} ? 1 : 0;

   return $rdata; 
}

#write the line to destination file
sub write_line {
  my $content = shift;
  open  (OUT, '>>:encoding(UTF-8)', $dest);
  $| = 1; # Before writing!
  print  OUT $content;
  close (OUT);
  OUT->autoflush(1); # After writing!
}

### MAIN ###
#Remove existing data and destination directory, and write the processed content therein
unlink $dest if (-e $dest);
process_file($file);
