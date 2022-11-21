//author - Nayanamana Samarasinghe

//Methods to avoid detection of an automated crawler
//-----------------
const preparePageForTests = async (page) => {

   // Pass the Webdriver Test.
   await page.evaluateOnNewDocument(() => {
     Object.defineProperty(navigator, 'webdriver', {
       get: () => false,
     });
   });

  // Pass the Chrome Test.
  await page.evaluateOnNewDocument(() => {
    // We can mock this in as much depth as we need for the test.
    window.navigator.chrome = {
      runtime: {},
      // etc.
    };
  });

  // Pass the Permissions Test.
  await page.evaluateOnNewDocument(() => {
    const originalQuery = window.navigator.permissions.query;
    return window.navigator.permissions.query = (parameters) => (
      parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
    );
  });

  // Pass the Plugins Length Test.
  await page.evaluateOnNewDocument(() => {
    // Overwrite the `plugins` property to use a custom getter.
    Object.defineProperty(navigator, 'plugins', {
      // This just needs to have `length > 0` for the current test,
      // but we could mock the plugins too if necessary.
      get: () => [1, 2, 3, 4, 5],
    });
  });

  // Pass the Languages Test.
  await page.evaluateOnNewDocument(() => {
    // Overwrite the `plugins` property to use a custom getter.
    Object.defineProperty(navigator, 'languages', {
      //get: () => ['en-US', 'en'],
        get: () => ['fr-US', 'fr'],
    });
  });

}
//-----------------


module.exports =
{
    run_crawl_multiple_urls : run_crawl_multiple_urls,
}

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const devices = require('puppeteer/DeviceDescriptors');
const globalDir = './';

const tout = 30000; //10000;
const twaitFor = 500; //2000;
const vp_width = 1200;
const vp_height = 900;

//const home_dir = require('os').homedir();
const home_dir = '/mnt/extra2/projects/0919_cl';

//Terminate the process in case some weird things happen
process.on('unhandledRejection', up => { 
   //throw up 
   console.log("ERROR: TERMINATE DUE TO ERRORS...");
   console.log(up)
});

async function run_crawl_multiple_urls(urlList, nameList, globalDir, site_index, no_max_urls){

  //Set Googlebot user-agent
  googlebot_crawler_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
  //Set Chrome user-agent
  chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
  //Set IE user-agent
  ie_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
  //Set BingBot user-agent
  bing_ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";

  //Chrome (Anfroid) user agent
  chrome_android_ua = "Mozilla/5.0 (Linux; Android 8.0.0; TA-1053 Build/OPR1.170623.026) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3368.0 Mobile Safari/537.36";

  if (site_index == 1) {
    //Delete all files in results directory
    const fileDir = home_dir + '/cloaking/results/';
    fs.readdir(fileDir, (err, files) => {
      if (err) throw err;

      for (const file of files) {
        fs.unlink(path.join(fileDir, file), err => {
          if (err) throw err;
          });
      }
    });
  }

  var arrayLength = urlList.length;
  var user_agents = [{'label': 'GOOGLEBOT', 'ua':  googlebot_crawler_ua}, {'label': 'CHROME', 'ua':  chrome_ua}];
  var iter_arr = [1,2];

  var counter = 0;

  for (var i = 0; i < arrayLength; i++) {
  
    counter = counter + 1;
    if (site_index < arrayLength && counter < site_index) {
      continue;
    }

    if (counter > no_max_urls) {
        break;
        //process.on( 'SIGINT', function() {
        //  console.log( counter + " exceeds " + no_max_urls +"\nGracefully shutting down from SIGINT (Ctrl-C)" );
          // some other closing procedures go here
        //  process.exit();
       //})
    }

    //the i-th element
    var myUrl = urlList[i];
    console.log("[SITE_VISIT]	" + myUrl);

    var arrayOfStrings = String(myUrl).split('/');
    var name = globalDir + nameList[i];

    for (j = 0; j < iter_arr.length; j++) {
       iter_no = iter_arr[j];
       for (k = 0; k < user_agents.length; k++) {
           ua = user_agents[k]['ua']
           label = user_agents[k]['label']

           let browser = null
           let page = null

           try {
               //let args = puppeteer.defaultArgs().filter(arg => arg !== '--disable-client-side-phishing-detection');
               let args = puppeteer.defaultArgs();
               //args = puppeteer.defaultArgs().filter(arg => arg !==  '--safebrowsing-disable-auto-update');
               //args.splice(args.indexOf('--disable-client-side-phishing-detection'), 1 );
               //args.splice(args.indexOf('--safebrowsing-disable-auto-update'), 1 );
               args.push('--no-sandbox', '--disable-infobars')
               //console.log(args)
               browser = await puppeteer.launch({ ignoreDefaultArgs: true, args })
               
               //browser = await puppeteer.launch({args: ['--no-sandbox', '--disable-infobars']});
               page = await browser.newPage();

               ///////////
               //Set extra HTTP headers to avoid websites to detect automated crawler
               //await page.setExtraHTTPHeaders(
               //     {'Accept-Language': 'en-CA,en-US;q=0.9,en-GB;q=0.8,en;q=0.7',
               //         'naya': '123'},
               //);

               await page.setUserAgent(ua);
               //REMOVE IF ANY ISSUES ARE SEEN
               await preparePageForTests(page);
               let response = null
               let url = null


               //Request (goto) the URL
               try {
                    console.log("[TEST]	" + (i+1) + "	"  + label + "-" + iter_no + "	" + myUrl);
                    response = await page.goto(myUrl,  { timeout: tout, waitUntil: 'networkidle0' });
                    await page.waitFor(twaitFor);
                    url = await page.url();
               } catch (e0) {
                    console.log("[ERROR_TEST]	" + label + "-" + iter_no + "	" +  myUrl + "	" + e0);
                    throw "[ERROR_TEST]	" + e0;
               }


               //Record rediretcions
               try {
                   let directionChain = 'Redirection: from url:<' + myUrl + '> to <' + url + '>';

                   await fs.writeFile(name + '.' + label.toLowerCase()  + '_' + iter_no + '.redirect', directionChain, (err_redir) => {
                      if (err_redir) {
                         console.log("ERROR_REDIR_W:	" + label + "-" + iter_no + "	" + myUrl + "	" +  err_redir);
                         //throw err_redir;
                      }
                   });
               } catch (e1) {
                   console.log("[ERROR_REDIRECTION]	" + label + "-" + iter_no  + "	" +  myUrl + "	" + e1);
                   //throw "[ERROR_REDIRECTION] " +  e1;
               }

               //Record headers
               try {
                   let headers = JSON.stringify(response.headers());
                   await fs.writeFile(name + '.' + label.toLowerCase()  + '_' + iter_no  + '.headers', headers, (err_headers) => {
                      if (err_headers) {
                         console.log("ERROR_HD_W:	" + label + "-" + iter_no + "	" + myUrl + "	" + err_headers);
                         //throw err_headers;
                      }
                    });
                } catch (e2) {
                   console.log("[ERROR_HEADERS]	" + label + "-" + iter_no + "	" + myUrl + "   " + e2);
                   //throw "[ERROR_HEADERS] " + e2;
                   //Do not skpi
                }

                //Evaluate page content (after dynamic rendering)
                try {
                   //let HTML = await page.content(); //content is enough for the HTML content
                   let HTML = await page.$eval('html', el => el.innerHTML );
                   let filepath = name + '.source.'  + label.toLowerCase()  + '_' + iter_no + '.txt';
                   await fs.writeFile(filepath, HTML, (err_content) => {
                     if (err_content) {
                        console.log("ERROR_CON_W:	" + label + "-" + iter_no + "	" + myUrl + "	" +  err_content);
                        throw err_content;
                     }
                   });
                } catch (e3) {
                   console.log("[ERROR_CONTENT]	" + label + "-" + iter_no + "	" + myUrl + "   " + e3);
                   throw "[ERROR_CONTENT] " + e3;
                }


                //Evaluate rendered content
                try {
                    let rendered_content = await page.$eval('html', el => el.innerText );
                    let filepath = name + '.rendered.'  + label.toLowerCase()  + '_' + iter_no + '.txt';
                    //console.log(rendered_content);
                   await fs.writeFile(filepath, rendered_content, (err_rendered_content) => {
                     if (err_rendered_content) {
                        console.log("ERROR_RENDERED_C_W:	" + label + "-" + iter_no + "	" + myUrl + "	" +  err_rendered_content);
                        throw err_rendered_content;
                     }
                   });
                } catch (e_r) {
                   console.log("[ERROR_RENDERED_CONTENT]	" + label + "-" + iter_no + "	" + myUrl + "	" + e_r);
                   throw "[ERROR_RENDERED_CONTENT] " + e_r;
                }


                //Get all dynamically created links
                try {
                   let hrefs = await page.$$eval('a', as => as.map(a => a.href)); 
                   let hrefs_json = JSON.stringify(hrefs);
                   let filepath = name + '.links.'  + label.toLowerCase()  + '_' + iter_no + '.txt';
                   await fs.writeFile(filepath, hrefs_json, (err_hrefs_json) => {
                     if (err_hrefs_json) {
                        console.log("ERROR_GEN_LINKS:	" + label + "-" + iter_no + "	" + myUrl + "	" +  err_hrefs_json);
                        //throw err_hrefs_json;
                     }
                   });
                   
                } catch (e_dl) {
                   console.log("[ERROR_LINKS]	" + label + "-" + iter_no + "	" + myUrl + "	" + e_dl);
                   //throw "[ERROR_LINKS] " + e_dl;
                   //Do not skip
                }

                //Get dynamically created document objects from iframes (especially links)
                for (const frame of page.mainFrame().childFrames()){
                  try {
                     let bodyHandle = await frame.$('body');
                     let raw_html = await frame.evaluate(body => body.innerHTML, bodyHandle);
                     let filepath = name + '.ifrm.'  + label.toLowerCase()  + '_' + iter_no + '.txt';
                     await fs.writeFile(filepath, raw_html, (err_ifrm) => {
                       if (err_ifrm) {
                          console.log("ERROR_FRAME_DOC:	" + label + "-" + iter_no + "	" + myUrl + "	" +  err_ifrm);
                          //throw err_ifrm;
                       }
                     });
                     //console.log(raw_html);
                     await bodyHandle.dispose();
                  } catch (e_df) {
                     console.log("[ERROR_FRAMES]	" + label + "-" + iter_no + "	" + myUrl + "	" + e_df);
                     //throw "[ERROR_FRAMES] " + e_df;
                     //continue;
                     //Do not skip
                  }
                }


                //Take page screenshot
                try {
                   await page.setViewport({width: vp_width, height: vp_height});
                   //await page.screenshot({path: name + '.screen.' + label.toLowerCase()  + '_' + iter_no  + '.png', fullPage: true});
                   await page.screenshot({path: name + '.screen.' + label.toLowerCase()  + '_' + iter_no  + '.png'});
                } catch (e4) {
                  console.log("[ERROR_SCREENSHOT]	" + label + "-" + iter_no + "	" + myUrl + "	" + e4);
                  throw "[ERROR_SCREENSHOT] " + e4;
                }

           }
          catch (e)
           {
              console.log("[ERROR_OUTER]	" + label + "-" + iter_no + "	" + myUrl + " 	" + e);
           }
          finally {
             try {
                await page.close();
                await browser.close();
            } catch (e_sub) {
               console.log("ERROR_IN_FINALLY	" + e_sub);
               continue; //continue to the next user-agent
            }
         }
      }
   }



  }


};

