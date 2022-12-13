# Secure Email - Content Filter Tool

## Dynamically Add or Delete Envelope Senders in Secure Email Content Filters

The Secure Email Content Filter Tool is designed to allow for dynamic addition or removal of individual envelope
sender addresses as part of an incident response process.
</br></br>
It is limited to best effort support only.

## Installation

 1. Install latest version of Python 3.x .
 2. Pull code from Github repository: “github.com/brebouch/SecureEmailAutomation”. Ensure requirements are met via “pip install -r requirements.txt”.
 3. Edit the config.yaml files with the appropriate information. Optionally, you can use the CLI arguments. If opting for CLI arguments, all the parameters must be entered (see Operation section below).

## Operation

Using the config.yaml for all the inputs, call the python script with your interpreter.
</br></br>
user@workstation % python3 main.py


#### For command line execution of input variables, append using the following syntax:
<pre>
--filter-name --sender --action --secure-email-url --admin-user --admin-password
* = required argument
* Name of the content filter to be modified
* Email address to be added or removed
* ADD or Delete from content filter
* IP address or hostname of Secure Email
* Username for user with permissions in Secure Email to modify content filters
* Password for user with permissions in Secure Email to modify content filters

</pre>


##### CLI Example 

<pre>
python3 main.py --secure-email-url SecureEmail.test.com --admin-user admin --admin-password ********* \
--filter-name TestContentFilter --sender MaliciousEmail@badguys.com --action add
</pre>
