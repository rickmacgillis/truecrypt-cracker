<?php
/**
 * Copyright 2015 Rick Mac Gillis
 * 
 * Example configuration file for TrueCrypt Cracker
 */

/*
 * Check how many password combinations there are for the generated portion of your password,
 * by using the tool at http://www.csgnetwork.com/optionspossiblecalc.html. I don't own that
 * site, and I'm not affiliated with it. I used it for my own calculations.
 */

include('./truecryptcracker.php');

$tcc = new \TrueCryptCracker\TrueCryptCracker();

// This is the list of possible characters your password contains.
$tcc->setPossibleChars('123456');

// If you know the first part of your password, you can set it with this method.
$tcc->setKnownPrefix('u324uh');

// If you know the last part of the password, you can set that here.
$tcc->setKnownSuffix('dsf87987');

// Set the length of the password to generate.
$tcc->setGenLength(4);

// Set the path to the encrypted volume or file.
$tcc->setVolumePath('/dev/sdb1');

// Set the directory in which to mount the encrypted file or device.
$tcc->setMountDir('/media/truecrypt');

// Set the log file for any stderr output.
$tcc->setStderrFile('/tmp/passerrors.log');

// Start crackin'!
$tcc->crack();
