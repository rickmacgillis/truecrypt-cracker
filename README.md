# TrueCrypt Cracker

I somehow forgot a portion of my password for my TrueCrypt device, so I wrote this program to help me crack my own password. If you need a reliable brute-force password cracker, you've found it. It cracks passwords intelligently by considering what you know about the password.

Requirements
------------

1. PHP 5.3+ (Must have access to proc_* functions and PHP-Cli!)
2. Linux system

Installation
------------

Either clone the repo or install it with composer.

`composer.phar require cozylife/truecrypt-cracker`

Usage
-----

Configure the script as shown in the example file. When you've finished your configuration, open a Bash console, cd to the directory of your script, and enter the following line.

`sudo php example.php`

Sudo is important as it gives PHP access to mount the device.

Tips
----

1. The script processes the possible characters list in order. Place the most likely characters first.
2. If you think that your password contains one combination of characters **or** another combination, run two tests to find the correct password.
3. If number two applies to you, run the tests in parallel by using multiple console windows. (You'll need to use multiple copies of your script to pull this off.)
