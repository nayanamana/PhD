from automation import TaskManager, CommandSequence
import sys, getopt
from pprint import pprint

def main(argv):
  try:
      opts, args = getopt.getopt(sys.argv[1:],'i:s:l:',['ifile=','snum=','limit='])
  except getopt.GetoptError:
      print 'demo.py -i <inputfile> s <snum> -l <limit>'
      sys.exit(2)

  #set default line number to 0
  slinenum = 0
  limit = 9999999999999 #set a large number to the site limit to be used

  if (not opts):
     print 'demo.py -i <inputfile> s <snum> -l <limit>'
     sys.exit()

  for opt, arg in opts:
    if opt == '-i':
         iAssigned = 1

    if opt in ("-i", "--ifile"):
         inputfile = arg
    elif opt in ("-s", "--snum"):
         slinenum = arg
    elif opt in ("-l", "--limit"):
         limit = arg

  if not iAssigned:
         print 'demo.py -i <inputfile> s <snum> -l <limit>'
         sys.exit()

  f = open(inputfile, 'r')
  sites = f.readlines()



  # The list of sites that we wish to crawl
  #NUM_BROWSERS = 3 
  NUM_BROWSERS = 3 
  #NUM_BROWSERS =2 
  #sites = ['http://www.74ypjqjwf6oejmax.onion/', 'http://www.example.com']

  # Loads the manager preference and 3 copies of the default browser dictionaries
  manager_params, browser_params = TaskManager.load_default_params(NUM_BROWSERS)

  # Update browser configuration (use this for per-browser settings)
  for i in xrange(NUM_BROWSERS):
    browser_params[i]['http_instrument'] = True # Record HTTP Requests and Responses
    browser_params[i]['js_instrument'] = True # Record JS method calls (for fingerprinting support)
    browser_params[i]['disable_flash'] = False #Enable flash for all three browsers
    browser_params[i]['cookie_instrument'] = True # To consider cookies set by both JS and HTTP responses
    #Naya - Launch all brower sessions in  a headless fashion
    browser_params[i]['headless'] = True #Launch all browsers headless

  #browser_params[0]['headless'] = True #Launch only browser 0 headless

  # Update TaskManager configuration (use this for crawl-wide settings)
  manager_params['data_directory'] = '~/Desktop/'
  manager_params['log_directory'] = '~/Desktop/'

  # Instantiates the measurement platform
  # Commands time out by default after 60 seconds
  manager = TaskManager.TaskManager(manager_params, browser_params)

  index = 0

  # Visits the sites with all browsers simultaneously
  for site in sites:
    index = index + 1
    if slinenum and (int(index) < int(slinenum)):
       continue
    if limit and (int(index) > int(limit)):
       break
    site = site.rstrip()
    #command_sequence = CommandSequence.CommandSequence(site)
    #Naya -launch stateless sessions to conserve resources
    command_sequence = CommandSequence.CommandSequence(site, reset=True)

    # Start by visiting the page
    command_sequence.get(sleep=30, timeout=60)
    #command_sequence.get(sleep=30, timeout=300) 
    #command_sequence.get(sleep=0, timeout=60)
    #command_sequence.get(sleep=0, timeout=240)

    # dump_profile_cookies/dump_flash_cookies closes the current tab.
    command_sequence.dump_profile_cookies(120)

    #Naya - dump page source
    #command_sequence.recursive_dump_page_source("pgsrc", timeout=60)
    #command_sequence.screenshot_full_page("srcpg", timeout=60)

    ##manager.execute_command_sequence(command_sequence, index='**') # ** = synchronized browsers
    manager.execute_command_sequence(command_sequence)
    #manager.execute_command_sequence(command_sequence, index='#')

    #Naya - dump page source
    #command_sequence.dump_page_source("pgsrc", timeout=60)
    #command_sequence.screenshot_full_page("srcpg", timeout=60)

  # Shuts down the browsers and waits for the data to finish logging
  manager.close()



if __name__ == "__main__":
   main(sys.argv[1:])
