README

More information on Censys can be found at https://www.censys.io/. A paid subscription or researcher access to Censys is required to extract data from it for which you may need to work with the Censys support team (support@censys.com). Access the data directly through the Google BigQuery interface. Additional information is available here: https://support.censys.io/google-bigquery/bigquery-introduction.

Below explains the details on how to extract the relevant device and Alexa site specific data from Censys, format the data to an intermediary format and analyzing the formatted data.

(1) Extract the relevant data for devices and Alexa sites following the instructions in https://support.censys.io/google-bigquery/adding-censys-datasets-to-bigquery. Queries to extract the data are shown below:

ALEXA SITES
-----------

SELECT
  alexa_rank,
  domain,
  TO_JSON_STRING(p443.https_www.tls.certificate.parsed.subject.country) arr,
  p443.https.tls.version,
  p443.https.tls.cipher_suite.name as cipher_suite_name,
  p443.https.tls.certificate.parsed.issuer_dn,
  p443.https.tls.certificate.parsed.subject_dn,
  p443.https.tls.certificate.parsed.validity.start,
  p443.https.tls.certificate.parsed.validity.end,
  p443.https.tls.certificate.parsed.signature.self_signed,
  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name as key_algorithm_name,
  p443.https.tls.certificate.parsed.signature.signature_algorithm.name as signature_algorithm_name,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca as is_ca,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
  p443.https.tls.server_key_exchange.rsa_params.modulus,
  p443.https.tls.signature.hash_algorithm,
  p443.https.tls.validation.browser_trusted,
  p443.https.dhe.dh_params.prime.value as dhe_prime_value,
  p443.https.dhe.dh_params.generator.value as dhe_generator_value,
  p443.https.tls.server_key_exchange.dh_params.prime.value as dh_prime_value,
  p443.https.tls.server_key_exchange.dh_params.generator.value as dh_generator_value,
  p443.https.tls.certificate.parsed.fingerprint_sha256
FROM
  `censys-io.domain_public.20180506`
WHERE
  alexa_rank IS NOT NULL AND alexa_rank < 1000001
GROUP BY
  alexa_rank,
  domain,
  arr,
  p443.https.tls.version,
  p443.https.tls.cipher_suite.name,
  p443.https.tls.certificate.parsed.issuer_dn,
  p443.https.tls.certificate.parsed.subject_dn,
  p443.https.tls.certificate.parsed.validity.start,
  p443.https.tls.certificate.parsed.validity.end,
  p443.https.tls.certificate.parsed.signature.self_signed,
  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name,
  p443.https.tls.certificate.parsed.signature.signature_algorithm.name,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
  p443.https.tls.server_key_exchange.rsa_params.modulus,
  p443.https.tls.signature.hash_algorithm,
  p443.https.tls.validation.browser_trusted,
  p443.https.dhe.dh_params.prime.value,
  p443.https.dhe.dh_params.generator.value,
  p443.https.tls.server_key_exchange.dh_params.prime.value,
  p443.https.tls.server_key_exchange.dh_params.generator.value,
  p443.https.tls.certificate.parsed.fingerprint_sha256,
  p443.https_www.tls.certificate.parsed.extensions.basic_constraints.is_ca

DEVICES
-------

SELECT
  metadata.device_type,
  metadata.manufacturer,
  location.country,
  p443.https.tls.cipher_suite.name as cipher_suite_name,
  p443.https.tls.version as tls_version,
  p443.https.tls.certificate.parsed.subject_dn,
  p443.https.tls.certificate.parsed.validity.start,
  p443.https.tls.certificate.parsed.validity.end,
  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name as key_algorithm_name,
  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
  p443.https.tls.server_key_exchange.rsa_params.modulus,
  p443.https.tls.certificate.parsed.issuer_dn,
  p443.https.tls.certificate.parsed.version,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca,
  p443.https.tls.certificate.parsed.signature.self_signed,
  p443.https.tls.certificate.parsed.signature.signature_algorithm.name as sig_algorithm_name,
  p443.https.tls.signature.hash_algorithm,
  p443.https.tls.validation.browser_trusted,
  p443.https.tls.server_key_exchange.dh_params.prime.value as dh_prime_value,
  p443.https.tls.server_key_exchange.dh_params.generator.value as dh_gen_value,
  p443.https.dhe_export.dh_params.prime.value as dhe_prime_value,
  p443.https.dhe_export.dh_params.generator.value as dhe_gen_value,
  p443.https.tls.certificate.parsed.fingerprint_sha256,
  ip
FROM
  `censys-io.ipv4_public.20180506`
WHERE
  metadata.device_type IS NOT NULL
GROUP BY
  metadata.device_type,
  metadata.manufacturer,
  location.country,
  p443.https.tls.cipher_suite.name,
  p443.https.tls.version,
  p443.https.tls.certificate.parsed.subject_dn,
  p443.https.tls.certificate.parsed.validity.start,
  p443.https.tls.certificate.parsed.validity.end,
  p443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name,
  p443.https.tls.certificate.parsed.subject_key_info.rsa_public_key.length,
  p443.https.tls.server_key_exchange.rsa_params.modulus,
  p443.https.tls.certificate.parsed.issuer_dn,
  p443.https.tls.certificate.parsed.version,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.max_path_len,
  p443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca,
  p443.https.tls.certificate.parsed.signature.self_signed,
  p443.https.tls.certificate.parsed.signature.signature_algorithm.name,
  p443.https.tls.signature.hash_algorithm,
  p443.https.tls.validation.browser_trusted,
  p443.https.tls.server_key_exchange.dh_params.prime.value,
  p443.https.tls.server_key_exchange.dh_params.generator.value,
  p443.https.dhe_export.dh_params.prime.value,
  p443.https.dhe_export.dh_params.generator.value,
  p443.https.tls.certificate.parsed.fingerprint_sha256,
  ip

(2) Download the data to a folder 
(3) Format the data for Alexa websites using script: format_webapp_data.pl
    ./format_webapp_data.pl -d <destination output file> -f <input data file>
    Example:
   ./format_webapp_data.pl -d '/home/naya/fc_ext/scripts/data/090518/alexa_domains' -f '/home/naya/fc_ext/scripts/data/090518/alexa_domains_090518-2-000000000000'
(4) Format the data for Alexa websites using script: format_device_data.pl
    ./format_device_data.pl -d <destination output file> -f <input data file>
    Example:
   ./format_device_data.pl -d '/home/naya/fc_ext/scripts/data/090518/device_data' -f '/home/naya/fc_ext/scripts/data/090518/devices_090518_1-00000000000_all'
(5) Analyze using the formatted device data (4) and Alexa site data (3) extracted from previous steps using script: process_device_info.pl
. The results from the analysis will be written to output destination path.
    ./process_device_info.pl -d <destination output file> -i <proccesed device data file> -a <processed alexa website data file>
    Example:
    ./process_device_info.pl -d '/home/naya/fc_ext/scripts/out/analysis/' -i '/home/naya/fc_ext/scripts/data/090518/device_data' -a '/home/naya/fc_ext/scripts/data/090518/alexa_domains' 







