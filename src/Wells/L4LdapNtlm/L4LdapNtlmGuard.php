<?php namespace Wells\L4LdapNtlm;

use Illuminate\Auth\Guard;

/**
 * An LDAP/NTLM authentication driver for Laravel 4.
 *
 * @author Brian Wells (https://github.com/wells/)
 * 
 */
class L4LdapNtlmGuard extends Guard
{
	public function admin()
	{
		// Check if user is logged in
		if ($this->check() && $this->user())
		{
			// User type is admin = 0
		    return $this->user()->type == 0;
		}
		return FALSE;
	}

	public function auto()
	{
		if ($this->check())
			return TRUE;

		// Should return FALSE if libapache2-mod-auth-ntlm-winbind is not installed
		if (! isset($_SERVER['REMOTE_USER']))
			return FALSE;

		$ntlm = explode('\\', $_SERVER['REMOTE_USER']);

		if (count($ntlm) != 2)
			return FALSE;

		$credentials = array(
			'username' => strtolower($ntlm[1]),
			'NTLM' => TRUE
		);

		return $this->attempt($credentials, TRUE);
	}
}