<?php
/**
 * Copyright 2015 Rick Mac Gillis
 * 
 * Brute-force password cracker for TrueCrypt volumes
 */

namespace TrueCryptCracker;

class TrueCryptCrackerInvalidResourceException extends \Exception{}

class TrueCryptCracker
{
	/**
	 * Possible characters for the password
	 * @var string $possibleChars
	 */
	protected $possibleChars = null;
	
	/**
	 * The string length of $this->possibleChars
	 * @var int $lenPossibleChars
	 */
	protected $lenPossibleChars = 0;
	
	/**
	 * The known first part of the password
	 * @var string $prefix
	 */
	protected $prefix = null;
	
	/**
	 * The known last part of the password
	 * @var string $suffix
	 */
	protected $suffix = null;
	
	/**
	 * The voulume to mount
	 * @var string $volumePath
	 */
	protected $volumePath = null;
	
	/**
	 * The directory on which to mount the volume
	 * @var string $mountDir
	 */
	protected $mountDir = null;
	
	/**
	 * The file in which to write stderr messages
	 * @var string $strerrFile
	 */
	protected $strerrFile = null;
	
	/**
	 * The size of the password to generate (Not including prefix/suffix)
	 * @var int $minGenLength
	 */
	protected $genLength = 0;
	
	/**
	 * The password getting generated
	 * @var string $password
	 */
	protected $password = null;
	
	/**
	 * The array of character pointers for password generation
	 * @var array $charPointers
	 */
	protected $charPointers = array();
	
	/**
	 * The number of pointers in $this->charPointers
	 * @var int $numCharPointers
	 */
	protected $numCharPointers = 0;
	
	/**
	 * Crack a TrueCrypt password.
	 * 
	 * @throws TrueCryptCrackerInvalidResourceException
	 */
	public function crack()
	{
		foreach ($this->getPassword() as $password) {
			
			$ptr = proc_open('bash', $this->getDescriptors(), $pipes);
			
			if (!is_resource($ptr)) {
				throw new TrueCryptCrackerInvalidResourceException();
			}
			
			$this->writeTryingPasswordMessage($password);
			
			fwrite($pipes[0], $this->getTrueCryptCommand($password));
			fclose($pipes[0]);
			
			$response = stream_get_contents($pipes[1]);
			fclose($pipes[1]);
			
			$this->handleResponse($response, $password);
			
			if ($this->foundCorrectPassword($response)) {
				
				proc_close($ptr);
				return true;
				
			}
	
		}

		proc_close($ptr);
		return false;
	}
	
	/**
	 * Set the list of possible characters in the password.
	 * 
	 * @param string $charList
	 */
	public function setPossibleChars($charList)
	{
		$this->possibleChars = $charList;
		$this->lenPossibleChars = strlen($charList);
	}
	
	/**
	 * Set the known first part of the password.
	 * 
	 * @param string $prefix
	 */
	public function setKnownPrefix($prefix)
	{
		$this->prefix = $prefix;
	}
	
	/**
	 * Set the known last part of the password.
	 * 
	 * @param string $suffix
	 */
	public function setKnownSuffix($suffix)
	{
		$this->suffix = $suffix;
	}
	
	/**
	 * Set the volume to mount.
	 * 
	 * @param string $path
	 */
	public function setVolumePath($path)
	{
		$this->volumePath = $path;
	}
	
	/**
	 * Set the directory in which to mount the volume.
	 * 
	 * @param string $dir
	 */
	public function setMountDir($dir)
	{
		$this->mountDir = $dir;
	}
	
	/**
	 * Set the file to use for stderr messages.
	 * 
	 * @param string $file
	 */
	public function setStderrFile($file) {
		$this->strerrFile = $file;
	}
	
	/**
	 * Set the minimum length of the password to generate.
	 * 
	 * @param int $len
	 */
	public function setGenLength($len)
	{
		$this->genLength = $len;
	}
	
	/**
	 * Generate a password of the desired length, based on the possible characters,
	 * @TODO Make an option to skip duplicates.
	 * 
	 * @return string
	 */
	protected function getPassword()
	{
		// Generate pointers for every position.
		$this->generatePointers();
		
		// Always true until it returns
		while ($this->morePasswordsArePossible()) {
		
			// For each pointer...
			for ($i = $this->numCharPointers-1; $i >= 0; $i--) {
				
				if ($this->handledPointerRollovers($i)) {
					continue;
				}
				
				if (!$this->isPointerValid($i)) {
					
					$this->addPasswordChar($this->charPointers[$i]-1);
					
					if ($this->isFirstPointer($i)) {
						
						// Last password
						yield $this->getWrappedPassword();
						$this->writePasswordNotFoundMessage();
						return;
						
					}
					
					continue;
					
				}
				
				$this->addPasswordChar($this->charPointers[$i]);
				$this->incrementLastCharPointer($i);
					
			}
			
			// Yield the password, then reset it for the next loop.
			yield $this->getWrappedPassword();
			$this->password = null;
			
		}
	}
	
	/**
	 * Generate the array of pointers for each character except the last one.
	 */
	protected function generatePointers()
	{
		for ($i = 0; $i < $this->genLength; $i++) {
			$this->charPointers[$i] = 0;
		}
		
		$this->numCharPointers = count($this->charPointers);
	}
	
	/**
	 * Check if there are more possible passwords based on the first pointer's position.
	 * 
	 * @return bool
	 */
	protected function morePasswordsArePossible()
	{
		return $this->charPointers[0] !== $this->lenPossibleChars;
	}
	
	/**
	 * Handle pointer rollovers if needed.
	 * 
	 * @param int $pointer	The pointer to possibly roll over
	 * 
	 * @return bool	True if they rolled over or false if not
	 */
	protected function handledPointerRollovers($pointer)
	{
		if ($this->pointersNeedRollover($pointer)) {
				
			$this->rolloverPointers($pointer);
				
			if ($this->isPointerValid($pointer)) {
		
				$this->addPasswordChar($this->charPointers[$pointer]-1);
				return true;
		
			}
				
		}
		
		return false;
	}
	
	/**
	 * Check if it's time for the pointers to roll over.
	 * 
	 * @param int $pointer	The pointer to check
	 * 
	 * @return bool
	 */
	protected function pointersNeedRollover($pointer)
	{
		if ($pointer !== $this->numCharPointers-1 && $this->charPointers[$pointer+1] === $this->lenPossibleChars) {
			return true;
		}
		
		return false;
	}
	
	/**
	 * Reset the previous pointer, and increment the current pointer.
	 * 
	 * @param int $pointer
	 */
	protected function rolloverPointers($pointer)
	{
		$this->charPointers[$pointer+1] = 0;
		$this->charPointers[$pointer]++;
	}
	
	/**
	 * Check if a pointer is pointing to a valid location.
	 * 
	 * @param int $pointer
	 * 
	 * @return bool
	 */
	protected function isPointerValid($pointer)
	{
		if ($this->charPointers[$pointer] !== $this->lenPossibleChars) {
			return true;
		}
		
		return false;
	}
	
	/**
	 * Add a character to the password.
	 * 
	 * @param int $position		The position of the char in the possibleChars array
	 * 
	 * @return string
	 */
	protected function addPasswordChar($position)
	{
		$this->password = $this->possibleChars[$position].$this->password;
	}
	
	/**
	 * Check if the pointer is pointing to the first character.
	 * 
	 * @param int $pointer
	 * 
	 * @return bool
	 */
	protected function isFirstPointer($pointer)
	{
		return $pointer === 0;
	}
	
	/**
	 * Increment the last char pointer.
	 * 
	 * @param int $pointer	The pointer index
	 */
	protected function incrementLastCharPointer($pointer)
	{
		if ($pointer === $this->numCharPointers-1) {
			$this->charPointers[$pointer]++;
		}
	}
	
	/**
	 * Get the password with the prefix and the suffix.
	 * 
	 * @return string
	 */
	protected function getWrappedPassword()
	{
		return $this->prefix.$this->password.$this->suffix;
	}
	
	/**
	 * Get the list of descriptors for interaction with the child process.
	 * 
	 * @return array
	 */
	protected function getDescriptors()
	{
		return array(
				0	=> array('pipe', 'r'),
				1	=> array('pipe', 'w'),
				2	=> array('file', $this->strerrFile, 'a'),
		);
	}
	
	/**
	 * Get the command line to interact with TrueCrypt.
	 * 
	 * @param string $password	The password to use
	 * @return string
	 */
	protected function getTrueCryptCommand($password)
	{
		return 'truecrypt -t -k="" --protect-hidden="no" --password='.
			escapeshellarg($password).' '.$this->volumePath.' '.$this->mountDir;
	}
	
	/**
	 * Display the message to let the evil genius know which password the
	 * script is currently trying.
	 * 
	 * @param string $password	The current password
	 */
	protected function writeTryingPasswordMessage($password)
	{
		$this->displayMessage('Trying password: '.$password);
	}
	
	/**
	 * Display a message to the evil genius.
	 * 
	 * @param string $message
	 */
	protected function displayMessage($message)
	{
		echo $message."\n";
	}
	
	/**
	 * Display the correct message to the evil genius depending on the response from TrueCrypt.
	 * 
	 * @param string $response
	 */
	protected function handleResponse($response, $password)
	{
		switch($response) {
			
			case $this->getMountedMessage():
				$this->writeAlreadyMountedMessage();
				break;
			
			case $this->getSuccessfulResponse():
				$this->writeFoundPasswordMessage($password);
				break;
				
			default:
				if ($response !== $this->getWrongPasswordMessage()) {
					
					/**
					 * @TODO In the future this should get logged so that it doesn't scroll
					 * off of the screen irretrievably.
					 */
					$this->writeUnhandledResponseMessage($response);
					
				}
				break;
		}
	}
	
	/**
	 * Check if the response from TrueCrypt signified that we found the correct password.
	 * 
	 * @param string $response
	 */
	protected function foundCorrectPassword($response)
	{
		if ($response === $this->getMountedMessage() || $response === $this->getSuccessfulResponse()) {
			return true;
		}
		
		return false;
	}
	
	/**
	 * Get the message that TrueCrypt returns when a volume is mounted.
	 * 
	 * @return string
	 */
	protected function getMountedMessage()
	{
		return "The volume \"".$this->volumePath."\" is already mounted.\n";
	}
	
	/**
	 * Display a notice stating that the device is already mounted.
	 */
	protected function writeAlreadyMountedMessage()
	{
		$this->displayMessage($this->getMountedMessage());
	}
	
	/**
	 * Get the message that TrueCrypt returns when the script successfully mounts the volume.
	 * 
	 * @return string
	 */
	protected function getSuccessfulResponse()
	{
		return '';
	}
	
	/**
	 * Display the message informing the evil genius of the password the script
	 * has uncovered.
	 * 
	 * @param string $password	The password the script uncovered
	 */
	protected function writeFoundPasswordMessage($password)
	{
		$this->displayMessage('The password for the volume is: '.$password);
	}
	
	/**
	 * Get the message that TrueCrypt returns for an invalid password.
	 * 
	 * @return string
	 */
	protected function getWrongPasswordMessage()
	{
		return "Incorrect password or not a TrueCrypt volume.\n\nEnter password for ".$this->volumePath.": ";
	}
	
	/**
	 * Display the message that TrueCrypt responded with, that the script isn't
	 * designed to handle.
	 * 
	 * @param string $message
	 */
	protected function writeUnhandledResponseMessage($message)
	{
		$this->displayMessage('TrueCrypt said: '.$message);
	}
	
	/**
	 * Display a message to indicate that the script could not find the password for the device.
	 */
	protected function writePasswordNotFoundMessage()
	{
		$this->displayMessage('Unfortunately the script could not find your password, evil genious.');
	}
}
