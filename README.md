# TrueCrypt Cracker

I somehow forgot a portion of my password for my TrueCrypt device, so I wrote this program to help me crack my own password. If you need a reliable brute-force password cracker, you've found it. It cracks passwords intelligently by considering what you know about the password.

Requirements
------------

1. PHP 5.3+ (Must have access to proc_* functions and PHP-Cli!)
2. Linux system

Usage
-----

Configure the script as shown in the example file. When you've finished your configuration, open a Bash console, cd to the directory of your script, and enter the following line.

`sudo php example.php`

Sudo is important as it gives PHP access to mount the device.
