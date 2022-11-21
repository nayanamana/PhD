#!/usr/bin/perl

#Analyze the intermidiary device and alexa data to output various measurements. Feel free to extend this script

use strict;
use warnings;

$|=1;

use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Request;
use JSON;
use Data::Dumper;

use Encode qw(encode decode);

use Getopt::Long;
use Tree::Simple;
use Tree::Parser;
use Date::Manip;

use File::Sip;
use File::Basename;
use Math::Round;

my $i_file;
my $a_file;
my $dest;

my $d_loc;
my $d_dev;
my $d_manu;
my $d_br_tr;
my $d_dbm;
my $d_iss_ou;
my $d_sub_ou;
my $d_dh_prime;
my $d_same_fp;
my $d_same_fp_cn;


GetOptions ("iotfile=s" =>\$i_file, "alexafile=s" => \$a_file,
            "destination=s" =>\$dest) or die ("Error in command line arguements\n");

die "Not all options specified:\n\n$0 -d <destination output path> -i <processed device data file> -a <processed alexa website data file>\n\nExample:\n$0 -d '/home/naya/fc_ext/scripts/out/analysis/' -i '/home/naya/fc_ext/scripts/data/090518/device_data' -a '/home/naya/fc_ext/scripts/data/090518/alexa_domains'\n" unless ($i_file && $a_file && (-e $i_file) && (-e $a_file) && -d dirname($dest));


my $d_data = {};
my $dd_data = {};
my $a_data = {};

open (my $fh_i, '<:encoding(UTF-8)', $i_file) or die "Could not open file '$i_file' $!";
open (my $fh_a, '<:encoding(UTF-8)', $a_file) or die "Could not open file '$a_file' $!";

#counter is to skip processing the header
my $counter = 0;

#Read processed device input data
while (my $row = <$fh_i>) {
   chomp $row;
   next unless $row;
   $counter++ ; #to skip the header
   next if $counter == 1;

   my @arr = split '	', $row;
   my $device = $arr[0] ? $arr[0] : '';
   my $manufacturer = $arr[1]  ? $arr[1] : '';
   my $ip = $arr[2]  ? $arr[2] : '';
   my $country =  $arr[3]  ? $arr[3] : '';
   my $tls_version = $arr[4]  ? $arr[4] : '';
   my $cipher_suite = $arr[5]  ? $arr[5] : '';
   my $key_ex_auth_alg = $arr[6]  ? $arr[6] : '';
   my $key_en_alg = $arr[7]  ? $arr[7] : '';
   my $hash_alg = $arr[8]  ? $arr[8] : '';
   my $sub_dn = $arr[9] ? $arr[9] : '';
   my $sub_org = $arr[11] ? $arr[11] : '';
   my $iss_org = $arr[12] ? $arr[12] : '';
   my $validity_start = $arr[13]  ? $arr[13] : '';
   my $validity_end = $arr[14]  ? $arr[14] : '';

   unless ($cipher_suite) {
       next; #Ignore if cipher suite is empty
   }

   my ($validity_period, $months_to_expire, $is_exp_cert, $is_invalid_validity, $is_validity_long) = ("","","","","");

   if ($arr[15] && $arr[16]) {
      $validity_period = $arr[15]  ? round($arr[15]/30) : ''; #in months
      $months_to_expire = $arr[16]  ? round($arr[16]/30) : '';#in months
      $is_exp_cert = ($months_to_expire && $months_to_expire < 0) ? 1 : '';
      $is_invalid_validity = ($validity_period && $validity_period < 0) ? 1 : '';
      $is_validity_long = ($arr[15] &&  $arr[15]/30 > 39 ) ? 1 : 0; #if validity period more than 39 months,assuming 30 days for a month
   }

   my $self_signed  = $arr[17]  ? $arr[17] : ''; 
   my $key_length = $arr[18]  ? $arr[18] : '';
   my $key_alg_name = $arr[19] ? $arr[19] : '';
   my $sig_alg_name = $arr[20]  ? $arr[20] : '';
   my $is_ca = $arr[21] ? $arr[21] : '';
   my $browser_tr = $arr[22] ? $arr[22] : '';
   my $dh_prime = $arr[23] ? $arr[23] : '';
   my $dh_gen = $arr[24] ? $arr[24] : '';
   my $fp = $arr[25] ? $arr[25] : '';

   #From here, we record counts of different cryptographic parameters
   $d_loc->{$country}++;
   $d_dev->{$device}++;
   $d_manu->{$manufacturer}++;
   $d_dbm->{$device}->{$manufacturer}++;

   next unless $cipher_suite;

   $d_br_tr->{tr}->{$country} = 0 unless $d_br_tr->{tr}->{$country};
   $d_br_tr->{utr}->{$country} = 0 unless $d_br_tr->{utr}->{$country};

   $browser_tr ? $d_br_tr->{tr}->{$country}++ : $d_br_tr->{utr}->{$country}++;
   $d_iss_ou->{$iss_org}++ if ((!$self_signed) && $iss_org);
   $d_sub_ou->{$sub_org}++ if ((!$self_signed) && $sub_org); 

   $d_dh_prime->{$device}->{c}->{$dh_prime}++ if ($dh_prime); 
   $d_dh_prime->{$device}->{manu}->{$manufacturer} = 1 if ($dh_prime);
   $d_same_fp->{$device}->{$fp}->{cnt}++ if ($fp);
   my @dev_cn;
   my $sub_cn = '';
   if ($sub_dn) {        
      @dev_cn = split ",", $sub_dn;
      foreach my $c (@dev_cn) {
           if ($c =~ /CN=(.*)/) {
               $sub_cn = $1;
               last;
           }
      }
      if ($sub_cn && $fp) {
            $d_same_fp->{$device}->{$fp}->{cn}->{$sub_cn}++ ;
      }
   }

   $d_data->{$device}->{tls_version}->{n}->{$tls_version}++;
   $d_data->{$device}->{key_ex_auth_alg}->{n}->{$key_ex_auth_alg}++;
   $d_data->{$device}->{key_en_alg}->{n}->{$key_en_alg}++;
   $d_data->{$device}->{hash_alg}->{n}->{$hash_alg}++;
   $d_data->{$device}->{validity_period}->{n}->{$validity_period}++;
   $d_data->{$device}->{months_to_expire}->{n}->{$months_to_expire}++;
   $d_data->{$device}->{self_signed}->{n}->{$self_signed}++;
   $d_data->{$device}->{key_length}->{n}->{$key_length}++;
   $d_data->{$device}->{sig_alg_name}->{n}->{$sig_alg_name}++ ;#if ($is_ca);
   $d_data->{$device}->{is_exp_cert}->{n}->{$is_exp_cert}++;
   $d_data->{$device}->{is_invalid_validity}->{n}->{$is_invalid_validity}++;
   $d_data->{$device}->{is_validity_long}->{n}->{$is_validity_long}++;
   $d_data->{$device}->{key_alg_name}->{n}->{$key_alg_name}++; 
   $d_data->{$device}->{is_ca}->{n}->{$is_ca}++;
   $d_data->{$device}->{browser_tr}->{n}->{$browser_tr}++;

   $dd_data->{tls_version}->{n}->{$tls_version}++;
   $dd_data->{key_ex_auth_alg}->{n}->{$key_ex_auth_alg}++;
   $dd_data->{key_en_alg}->{n}->{$key_en_alg}++;
   $dd_data->{hash_alg}->{n}->{$hash_alg}++;
   $dd_data->{validity_period}->{n}->{$validity_period}++;
   $dd_data->{months_to_expire}->{n}->{$months_to_expire}++;
   $dd_data->{self_signed}->{n}->{$self_signed}++;
   $dd_data->{key_length}->{n}->{$key_length}++;
   $dd_data->{sig_alg_name}->{n}->{$sig_alg_name}++; # if ($is_ca);
   $dd_data->{is_exp_cert}->{n}->{$is_exp_cert}++;
   $dd_data->{is_invalid_validity}->{n}->{$is_invalid_validity}++;
   $dd_data->{is_validity_long}->{n}->{$is_validity_long}++;
   $dd_data->{key_alg_name}->{n}->{$key_alg_name}++; 
   $dd_data->{is_ca}->{n}->{$is_ca}++;
   $dd_data->{browser_tr}->{n}->{$browser_tr}++;

}

#reset the counter before formatted data of alexa sites
#counter is to not to process the header
$counter = 0;

while (my $row = <$fh_a>) {
   chomp $row;
   next unless $row;
   $counter++ ; #to skip the header
   next if $counter == 1;

   my @arr = split '	', $row;
   my $country =  $arr[0]  ? $arr[0] : '';
   my $tls_version = $arr[1]  ? $arr[1] : '';
   my $cipher_suite = $arr[2]  ? $arr[2] : '';
   my $key_ex_auth_alg = $arr[3]  ? $arr[3] : '';
   my $key_en_alg = $arr[4]  ? $arr[4] : '';
   my $hash_alg = $arr[5]  ? $arr[5] : '';
   my $sub_org = $arr[6] ? $arr[6] : '';
   my $iss_org = $arr[7] ? $arr[7] : '';
   my $validity_start = $arr[10]  ? $arr[10] : '';
   my $validity_end = $arr[11]  ? $arr[11] : '';
   my $validity_period = $arr[12]  ? round($arr[12]/30) : ''; #in months
   my $months_to_expire = ($arr[13] && $arr[13] =~ /^\d+$/)  ? round($arr[13]/30) : '';#in months
   my $is_exp_cert = ($months_to_expire && $months_to_expire < 0) ? 1 : '';
   my $is_invalid_validity = ($validity_period && $validity_period < 0) ? 1 : '';
   my $is_validity_long = ($arr[12] &&  $arr[12]/30 > 39 ) ? 1 : 0; #if validity period more than 39 months,assuming 30 days for a month
   my $self_signed  = $arr[14]  ? $arr[14] : '';
   my $key_length = $arr[15]  ? $arr[15] : '';
   my $key_alg_name = $arr[16] ? $arr[16] : '';
   my $sig_alg_name = $arr[17]  ? $arr[17] : '';
   my $is_ca = $arr[18] ? $arr[18] : '';
   my $browser_tr = $arr[19] ? $arr[19] : '';
   my $dh_prime = $arr[22] ? $arr[22] : '';
   my $dh_gen = $arr[23] ? $arr[23] : '';
   my $fp = $arr[24] ? $arr[24] : '';

   next unless $cipher_suite;

   $a_data->{tls_version}->{n}->{$tls_version}++;
   $a_data->{key_ex_auth_alg}->{n}->{$key_ex_auth_alg}++;
   $a_data->{key_en_alg}->{n}->{$key_en_alg}++;
   $a_data->{hash_alg}->{n}->{$hash_alg}++;
   $a_data->{validity_period}->{n}->{$validity_period}++;
   $a_data->{months_to_expire}->{n}->{$months_to_expire}++;
   $a_data->{self_signed}->{n}->{$self_signed}++;
   $a_data->{key_length}->{n}->{$key_length}++;
   $a_data->{sig_alg_name}->{n}->{$sig_alg_name}++ ; #if ($is_ca);
   $a_data->{is_exp_cert}->{n}->{$is_exp_cert}++;
   $a_data->{is_invalid_validity}->{n}->{$is_invalid_validity}++;
   $a_data->{is_validity_long}->{n}->{$is_validity_long}++;
   $a_data->{key_alg_name}->{n}->{$key_alg_name}++;
   $a_data->{is_ca}->{n}->{$is_ca}++;
   $a_data->{browser_tr}->{n}->{$browser_tr}++;
}


#Calculate percentage of cryptographic primitives of alexa sites
foreach my $k (keys %{$a_data}) {
      my @vals = values %{$a_data->{$k}->{n}};
      my $sum;
      map { $sum += $_ } @vals;
      foreach my $a (keys %{$a_data->{$k}->{n}}) {
         my $v = $a_data->{$k}->{n}->{$a};
         $a_data->{$k}->{p}->{$a} = nearest(0.1,($v/$sum)*100);
      }
}

#Calculate percentage of cryptographic primitives of device data (per device type, e.g., infra. router)
foreach my $d (keys %$d_data) {
   foreach my $k (keys %{$d_data->{$d}}) {
      #next if $k =~ /orank/;
      my @vals = values %{$d_data->{$d}->{$k}->{n}};
      my $sum;
      map { $sum += $_ } @vals;
      foreach my $a (keys %{$d_data->{$d}->{$k}->{n}}) {
         my $v = $d_data->{$d}->{$k}->{n}->{$a};
         $d_data->{$d}->{$k}->{p}->{$a} = nearest(0.1,($v/$sum)*100);
      }
   }
}

#Calculate percentage of cryptographic primitives of device data (for all device types collectively)
foreach my $k (keys %{$dd_data}) {
      my @vals = values %{$dd_data->{$k}->{n}};
      my $sum;
      map { $sum += $_ } @vals;
      foreach my $a (keys %{$dd_data->{$k}->{n}}) {
         my $v = $dd_data->{$k}->{n}->{$a};
         $dd_data->{$k}->{p}->{$a} = nearest(0.1,($v/$sum)*100);
      }
}



close $fh_i;
close $fh_a;

#write the measurements computer above to files in destination file
my $devices;
my $f_ddata;
my $f_adata;
my $f_dddata;

##Evaluate counts/percentages of device types for cryptographic primitives
foreach my $d (sort (keys %$d_data)) {
   $devices->{$d} = 1;
   foreach my $k (sort (keys %{$d_data->{$d}})) {
      my $attrs;
      foreach my $a (sort (keys %{$d_data->{$d}->{$k}->{n}})) {
          $attrs->{$a} = 1;
      }
  
      foreach my $a (sort (keys %$attrs)) {
          $f_ddata->{$k}->{$a}->{$d}->{n}  = $d_data->{$d}->{$k}->{n}->{$a};
          $f_ddata->{$k}->{$a}->{$d}->{p}  = $d_data->{$d}->{$k}->{p}->{$a};
      }

   }
}

##Evaluate overall devices counts/percentages for cryptographic primitives
foreach my $k (sort (keys %{$dd_data})) {
      my $attrs;
      foreach my $a (sort (keys %{$dd_data->{$k}->{n}})) {
          $attrs->{$a} = 1;
      }
 
      foreach my $a (sort (keys %$attrs)) {
          $f_dddata->{$k}->{$a}->{n}  = $dd_data->{$k}->{n}->{$a};
          $f_dddata->{$k}->{$a}->{p}  = $dd_data->{$k}->{p}->{$a};
      }

}

##Evaluate alexa site counts/percentages for cryptographic primitives
foreach my $k (sort (keys %{$a_data})) {
      my $attrs;
      foreach my $a (sort (keys %{$a_data->{$k}->{n}})) {
          $attrs->{$a} = 1;
      }
 
      foreach my $a (sort (keys %$attrs)) {
          $f_adata->{$k}->{$a}->{n}  = $a_data->{$k}->{n}->{$a};
          $f_adata->{$k}->{$a}->{p}  = $a_data->{$k}->{p}->{$a};
      }

}

#---------------------------------------------------------
#Write counts and percentages of device types for each cryptographic primitive
my @sorted_devices = sort(keys %$devices);

unlink "$dest/all_device_assessment" if -e "$dest/all_device_assessment";

open(my $fh1, '>', "$dest/all_device_assessment");

my $d_header = "Key	Attr";
foreach my $he (@sorted_devices) {
  $d_header .= "	$he (no)	$he (pct)"; 
}

print $fh1 "$d_header\n";

foreach my $k (sort (keys %$f_ddata)) {
   next if ($k =~ /months_to_expire|validity_period/);
   foreach my $a (sort (keys %{$f_ddata->{$k}})) {
       my $entry = "$k	$a";
       foreach my $sd (@sorted_devices) {
           my $n_val = $f_ddata->{$k}->{$a}->{$sd}->{n} ? $f_ddata->{$k}->{$a}->{$sd}->{n} : '';
           my $p_val = $f_ddata->{$k}->{$a}->{$sd}->{p} ? $f_ddata->{$k}->{$a}->{$sd}->{p} : '';
           $entry .= "	" . $n_val . "	" . $p_val ; 
       }
       print $fh1 "$entry\n";
   }
} 
close $fh1;

#-----------------
#Write relative percentages (taking alexa sites as a base) of device types for each of the cryptographic parameters
unlink "$dest/all_devices_rel_to_alexa" if -e "$dest/all_devices_rel_to_alexa";

open(my $fh2, '>', "$dest/all_devices_rel_to_alexa");

my $ad_header = "Key	Attr	Alexa";
foreach my $he (@sorted_devices) {
  $ad_header .= "	$he";
}

print $fh2 "$ad_header\n";

foreach my $k (sort (keys %$f_ddata)) {
   next if ($k =~ /months_to_expire|validity_period/);
   foreach my $a (sort (keys %{$f_ddata->{$k}})) {
       $f_adata->{$k}->{$a}->{p} = "" unless $f_adata->{$k}->{$a}->{p};
       my $entry = "$k	$a	" . $f_adata->{$k}->{$a}->{p};
       foreach my $sd (@sorted_devices) {
           my $p_val = ($f_adata->{$k}->{$a}->{p} && $f_ddata->{$k}->{$a}->{$sd}->{p}) ? nearest(0.01, - $f_adata->{$k}->{$a}->{p} + $f_ddata->{$k}->{$a}->{$sd}->{p}) : '';
           $entry .= "	" . $p_val ;
       }
       print $fh2 "$entry\n";
   }
}
close $fh2;

#---------------------
#Write percentages of device types for each cryptographic primitive
unlink "$dest/all_devices_comparison_pct" if -e "$dest/all_devices_comparison_pct";

open(my $fh2_1, '>', "$dest/all_devices_comparison_pct");

my $ad_header_1 = "Key	Attr";
foreach my $he (@sorted_devices) {
  $ad_header_1 .= "	$he";
}

print $fh2_1 "$ad_header_1\n";

foreach my $k (sort (keys %$f_ddata)) {
       next if ($k =~ /months_to_expire|validity_period/);
       foreach my $a (sort (keys %{$f_ddata->{$k}})) {
          my $entry = "$k	$a" ;
          foreach my $sd (@sorted_devices) {
             my $p_val = ($f_ddata->{$k}->{$a}->{$sd}->{p} ) ? nearest(0.01, $f_ddata->{$k}->{$a}->{$sd}->{p}) : '';
             $entry .= "	" . $p_val ;
          }
          print $fh2_1 "$entry\n";
      }
}
close $fh2_1;


#---------------------
#Write counts of device types for each cryptographic primitive
unlink "$dest/all_devices_comparison_abs" if -e "$dest/all_devices_comparison_abs";

open(my $fh2_2, '>', "$dest/all_devices_comparison_abs");

my $ad_header_2 = "Key	Attr";
foreach my $he (@sorted_devices) {
  $ad_header_2 .= "	$he";
}

print $fh2_2 "$ad_header_1\n";

foreach my $k (sort (keys %$f_ddata)) {
       next if ($k =~ /months_to_expire|validity_period/);
       foreach my $a (sort (keys %{$f_ddata->{$k}})) {
          my $entry = "$k	$a" ;
          foreach my $sd (@sorted_devices) {
             my $p_val = ($f_ddata->{$k}->{$a}->{$sd}->{n} ) ? nearest(0.01, $f_ddata->{$k}->{$a}->{$sd}->{n}) : '';
             $entry .= "	" . $p_val ;
          }
          print $fh2_2 "$entry\n";
      }
}
close $fh2_2;

#----------------------------

#Overall counts and percentages for all devices types followed by alexa sites
unlink "$dest/abs_all_devices_rel_to_alexa" if -e "$dest/abs_all_devices_rel_to_alexa";

open(my $fh21, '>', "$dest/abs_all_devices_rel_to_alexa");

my $abs_ad_header_dev = "Key	Attr	DPct	DCount";
my $abs_ad_header_alexa = "Key	Attr	APct	ACount";



print $fh21 "$abs_ad_header_dev\n";

foreach my $k (sort (keys %$f_dddata)) {
   next if ($k =~ /months_to_expire|validity_period/);
   foreach my $a (sort (keys %{$f_dddata->{$k}})) {
       $f_dddata->{$k}->{$a}->{p} = "" unless $f_dddata->{$k}->{$a}->{p};
       my $entry = "$k	$a	" . $f_dddata->{$k}->{$a}->{p} . "	" . $f_dddata->{$k}->{$a}->{n};
       print $fh21 "$entry\n";
   }
}

print $fh21 "\n\n$abs_ad_header_alexa\n";

foreach my $k (sort (keys %$f_adata)) {
   next if ($k =~ /months_to_expire|validity_period/);
   foreach my $a (sort (keys %{$f_adata->{$k}})) {
       $f_adata->{$k}->{$a}->{p} = "" unless $f_adata->{$k}->{$a}->{p};
       $f_adata->{$k}->{$a}->{n} = "" unless $f_adata->{$k}->{$a}->{n};
       my $entry = "$k	$a	" . $f_adata->{$k}->{$a}->{p} . "	" . $f_adata->{$k}->{$a}->{n};
       print $fh21 "$entry\n";
   }
}



close $fh21;

#---------------------

#Percentage and count of devices by location
my @arr_dbl =  (sort { $d_loc->{$a} <=> $d_loc->{$b} || $d_loc->{$a} cmp $d_loc->{$b} } keys %$d_loc);
my $sum_dbl;
map { $sum_dbl += $_ } values %$d_loc;


unlink "$dest/device_by_loc" if -e "$dest/device_by_loc";

open(my $fh3, '>', "$dest/device_by_loc");

my $dbl_header = "Country	Percentage of Devices	Number";

print $fh3 "$dbl_header\n";

foreach my $country (reverse @arr_dbl) {
    my $entry = $country . "	" . nearest(0.01, ($d_loc->{$country}/$sum_dbl)* 100) . "	" . $d_loc->{$country}; 
    print $fh3 "$entry\n";
}
close $fh3;

#--------------------
#Overall count and percentage of devices 
my @arr_dev =  (sort { $d_dev->{$a} <=> $d_dev->{$b} || $d_dev->{$a} cmp $d_dev->{$b} } keys %$d_dev);
my $sum_dev;
map { $sum_dev += $_ } values %$d_dev;


unlink "$dest/device_pct" if -e "$dest/device_pct";

open(my $fh4, '>', "$dest/device_pct");

my $dev_header = "Device	Percentage	Number";

print $fh4 "$dev_header\n";

foreach my $device (reverse @arr_dev) {
    my $entry = $device . "	" . nearest(0.001, ($d_dev->{$device}/$sum_dev)* 100) . "	" . $d_dev->{$device};
    print $fh4 "$entry\n";
}
close $fh4;

#--------------------
#Device percentage by manufacturer
my @arr_manu =  (sort { $d_manu->{$a} <=> $d_manu->{$b} || $d_manu->{$a} cmp $d_manu->{$b} } keys %$d_manu);
my $sum_manu;
map { $sum_manu += $_ } values %$d_manu;


unlink "$dest/manu_pct" if -e "$dest/manu_pct";

open(my $fh5, '>', "$dest/manu_pct");

my $manu_header = "Manufacturer	Percentage";

print $fh5 "$manu_header\n";

foreach my $manu (reverse @arr_manu) {
    my $entry = $manu . "	" . nearest(0.001, ($d_manu->{$manu}/$sum_manu)* 100);
    print $fh5 "$entry\n";
}
close $fh5;

#--------------------
#Browser trusted certificates by location
my @arr_br_tr =  (sort { $d_br_tr->{tr}->{$a} <=> $d_br_tr->{tr}->{$b} || $d_br_tr->{tr}->{$a} cmp $d_br_tr->{tr}->{$b} } keys %{$d_br_tr->{tr}});
my $sum_br_tr;
map { $sum_br_tr += $_ } values %{$d_br_tr->{tr}};
map { $sum_br_tr += $_ } values %{$d_br_tr->{utr}};

unlink "$dest/br_tr_by_loc" if -e "$dest/br_tr_by_loc";
unlink "$dest/dev_by_loc" if -e "$dest/dev_by_loc";

open(my $fh6, '>', "$dest/br_tr_by_loc");
open(my $fh6_1, '>', "$dest/dev_by_loc");

my $br_tr_by_loc_header = "Country	Percentage of Devices";
my $dev_by_loc_header = "Country	Percentage of Devices";

print $fh6 "$br_tr_by_loc_header\n";
print $fh6_1 "$dev_by_loc_header\n";

foreach my $country (reverse @arr_br_tr) {
    my $entry = $country . "	" . nearest(0.01, ($d_br_tr->{tr}->{$country}/$sum_br_tr)* 100);
    print $fh6 "$entry\n";
    $entry = $country . "	" . nearest(0.01, (($d_br_tr->{tr}->{$country} + $d_br_tr->{utr}->{$country})/$sum_br_tr)* 100);
    print $fh6_1 "$entry\n";
}
close $fh6;
close $fh6_1;

#--------------------
#Device percentage device type and manufacturer
unlink "$dest/dev_by_manu" if -e "$dest/dev_by_manu";

open(my $fh7, '>', "$dest/dev_by_manu");

my $dbm_header = "Device	Manufacturer	Percentage of Devices";

print $fh7 "$dbm_header\n";

foreach my $dev (reverse @arr_dev) {
    foreach my $manu (sort( keys %{$d_dbm->{$dev}})) {
       my $entry = $dev . "	" . $manu . "	" .  nearest(0.001, ($d_dbm->{$dev}->{$manu}/$sum_dev)* 100);
       print $fh7 "$entry\n";
    }
}
close $fh7;

#--------------------
#Device percentage by Issuer OU of certificates
my @arr_iss_ou =  (sort { $d_iss_ou->{$a} <=> $d_iss_ou->{$b} || $d_iss_ou->{$a} cmp $d_iss_ou->{$b} } keys %{$d_iss_ou});

unlink "$dest/iss_ou" if -e "$dest/iss_ou";

open(my $fh8, '>', "$dest/iss_ou");

my $iss_ou_header = "Issuer OU	Percentage of Device certicates";

print $fh8 "$iss_ou_header\n";

foreach my $ou (reverse @arr_iss_ou) {
    my $entry = $ou . "	" . nearest(0.001, ($d_iss_ou->{$ou}/$sum_dev)* 100);
    print $fh8 "$entry\n";
}
close $fh8;

#--------------------
#Device percentages by subject OU of certificates
my @arr_sub_ou =  (sort { $d_sub_ou->{$a} <=> $d_sub_ou->{$b} || $d_sub_ou->{$a} cmp $d_sub_ou->{$b} } keys %{$d_sub_ou});

unlink "$dest/sub_ou" if -e "$dest/sub_ou";

open(my $fh9, '>', "$dest/sub_ou");

my $sub_ou_header = "Subject OU	Percentage of Device certicates";

print $fh9 "$sub_ou_header\n";

foreach my $ou (reverse @arr_sub_ou) {
     my $entry = $ou . "	" . nearest(0.001, ($d_sub_ou->{$ou}/$sum_dev)* 100);
     print $fh9 "$entry\n";
}
close $fh9;

#--------------------
#Counts and percentages of device types and manufacturers having duplicate dh prime values
my $formatted_dh_prime;

foreach my $device (keys %$d_dh_prime) {
   foreach my $prime (keys %{$d_dh_prime->{$device}->{c}}) {
      $formatted_dh_prime->{$device} += $d_dh_prime->{$device}->{c}->{$prime};
   }
}


my @arr_dh_prime =  (sort { $formatted_dh_prime->{$a} <=> $formatted_dh_prime->{$b} || $formatted_dh_prime->{$a} cmp $formatted_dh_prime->{$b} } keys %{$formatted_dh_prime});

unlink "$dest/dh_prime" if -e "$dest/dh_prime";

open(my $fh10, '>', "$dest/dh_prime");

my $dh_prime_header = "Device	Percentage of duplicated dh prime values	Count	Manufacturers";

print $fh10 "$dh_prime_header\n";

foreach my $device (reverse @arr_dh_prime) {
   if ($formatted_dh_prime->{$device}>1) {
      my @m_arr = keys %{$d_dh_prime->{$device}->{manu}};
      my $entry = $device . "	" . nearest(0.001, ($formatted_dh_prime->{$device}/$sum_dev)* 100) . "	" . $formatted_dh_prime->{$device} ."	" . join("," ,@m_arr);
      print $fh10 "$entry\n";
   }
}

close $fh10;

#--------------------
#Counts and percentages of duplicate certificates of device types
my $formatted_fp;

foreach my $device (keys %{$d_same_fp}) {
   foreach my $fp (keys %{$d_same_fp->{$device}}) {
      #$formatted_fp->{$device} += $d_same_fp->{$device}->{$fp}->{cnt};
      $formatted_fp->{$device} += $d_same_fp->{$device}->{$fp}->{cnt} if ($d_same_fp->{$device}->{$fp}->{cnt} && $d_same_fp->{$device}->{$fp}->{cnt} > 1);
      if ( $formatted_fp->{$device} && $formatted_fp->{$device} > 1) {
            foreach my $cn (keys %{$d_same_fp->{$device}->{$fp}->{cn}}) {
              $d_same_fp_cn->{$cn} += $d_same_fp->{$device}->{$fp}->{cn}->{$cn};;
            }
      }
   }
}


my @arr_fp =  (sort { $formatted_fp->{$a} <=> $formatted_fp->{$b} || $formatted_fp->{$a} cmp $formatted_fp->{$b} } keys %{$formatted_fp});

unlink "$dest/dup_cert" if -e "$dest/dup_cert";

open(my $fh11, '>', "$dest/dup_cert");

my $dup_cert_header = "Device	Percentage of duplicate certificates	Number";

print $fh11 "$dup_cert_header\n";


foreach my $device (reverse @arr_fp) {
   if ($formatted_fp->{$device} > 1) {
      my $entry = $device . "	" . nearest(0.001, ($formatted_fp->{$device}/$sum_dev)* 100) ."	". $formatted_fp->{$device} ;
      print $fh11 "$entry\n";
   }
}

close $fh11;

#--------------------
#Counts and percentages of CN of duplicate device certificates
my @arr_dev_dup_cert_cn =  (sort { $d_same_fp_cn->{$a} <=> $d_same_fp_cn->{$b} || $d_same_fp_cn->{$a} cmp $d_same_fp_cn->{$b} } keys %{$d_same_fp_cn});

unlink "$dest/dev_dup_cert_cn" if -e "$dest/dev_dup_cert_cn";

open(my $fh12, '>', "$dest/dev_dup_cert_cn");

my $dev_dup_cert_cn_header = "CN	Pct	Number";

print $fh12 "$dev_dup_cert_cn_header\n";

foreach my $cn (reverse @arr_dev_dup_cert_cn) {
      my $entry = $cn . "	" . nearest(0.001, ($d_same_fp_cn->{$cn}/$sum_dev)* 100) ."	". $d_same_fp_cn->{$cn} ;
      print $fh12 "$entry\n";
}

close $fh12;


#--------------------

