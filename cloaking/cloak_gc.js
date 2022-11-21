#! /usr/bin/env node

var fs = require('fs');

//const home_dir = require('os').homedir();
const home_dir = '/mnt/extra2/projects/0919_cl';

//const googlebot = require('./googlebot');
//const crawl_multiple = require('./crawl_multiple');
const crawl_multiple = require('./crawl_multiple.js');

//Read site domains
//url_list_file = '/var/tmp/ph_sites_13'
//const url_list_file = home_dir + '/cloaking/data/ph_sites_1'
const url_list_file = '/home/naya/phd/ph_exp/results/all_cloaked_sites';
//url_list_file = '/var/tmp/cp1'
//const url_list_file = home_dir + '/cloaking/data/top_chinese_sites_1'

var array = fs.readFileSync(url_list_file).toString().split("\n");
var updated_array = []

for(i in array) {
//    console.log(array[i]);
    //updated_array.push('http://' + array[i]);
    updated_array.push(array[i]);
}

var without_prefix = []
for (i in updated_array) {
   p_url = updated_array[i].replace(/^https?:\/\//, '');
   without_prefix.push(p_url);
}

const output_dir = home_dir + "/cloaking/results/";

console.log("Run multiple tests for sites");

var urls = updated_array;
var names = without_prefix;

var site_index = 1;
var max_no_of_sites = 999999999999;

//print process.argv
process.argv.forEach(function (val, index, array) {
  //console.log(index + ': ' + val);
  if (index == 2) {
     site_index = val;
  }
  if (index == 3) {
     max_no_of_sites = val;
  }
});

crawl_multiple.run_crawl_multiple_urls(urls, names, output_dir, site_index, max_no_of_sites);
