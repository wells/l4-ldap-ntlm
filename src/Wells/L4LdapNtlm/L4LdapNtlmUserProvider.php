<?php namespace Wells\L4LdapNtlm;

use Illuminate\Auth\UserProviderInterface;
use Illuminate\Auth\UserInterface;
use Illuminate\Auth\GenericUser;

/**
 * An LDAP/NTLM authentication driver for Laravel 4.
 *
 * @author Brian Wells (https://github.com/wells/)
 * 
 */
class L4LdapNtlmUserProvider implements UserProviderInterface
{
	/**
	 * The Eloquent user model
	 * @var GenericUser
	 */
	protected $model;
	
	/**
	* Create a new LDAP user provider.
	*
	* @param  array  $config
	* @return void
	*/
	public function __construct($config)
	{
		$this->config = $config;

		// Connect to the domain controller
		if ( ! $this->conn = ldap_connect("ldap://{$this->config['host']}"))
		{
			throw new \Exception("Could not connect to LDAP host {$this->config['host']}: ".ldap_error($this->conn));
		}

		// Required for Windows AD
		ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);

		// Enable search of LDAP
		if ( ! @ldap_bind($this->conn, "{$this->config['dn_user']}@{$this->config['domain']}", $this->config['dn_pass']))
		{
			throw new \Exception('Could not bind to AD: '."{$this->config['dn_user']}@{$this->config['domain']}: ".ldap_error($this->conn));
		}
	}

	/**
	 * Destroy LDAP user provider
	 */
	public function __destruct()
	{
		if ( ! is_null($this->conn))
		{
			ldap_unbind($this->conn);
		}
	}

	/**
	 * Retrieve a user by by their unique identifier and "remember me" token.
	 *
	 * @param  mixed  $identifier
	 * @param  string  $token
	 * @return \Illuminate\Auth\UserInterface|null
	 */
	public function retrieveByToken($identifier, $token)
	{
		return $this->retrieveByID($identifier);
	}

	/**
	 * Update the "remember me" token for the given user in storage.
	 *
	 * @param  \Illuminate\Auth\UserInterface  $user
	 * @param  string  $token
	 * @return void
	 */
	public function updateRememberToken(UserInterface $user, $token)
	{
		$user->setRememberToken($token);
	}

	/**
	* Retrieve a user by their unique identifier.
	*
	* @param  mixed  $identifier
	* @return Illuminate\Auth\UserInterface|null
	*/
	public function retrieveByID($identifier)
	{
		$result = @ldap_read($this->conn, $identifier, '(objectclass=*)', $this->config['attributes']);
		if ($result === FALSE)
			return null;

		$entries = ldap_get_entries($this->conn, $result);
		if ($entries['count'] == 0 || $entries['count'] > 1)
			return null;

		return $this->clean($entries[0]);
	}

	/**
	* Retrieve a user by the given credentials.
	*
	* @param  array  $credentials
	* @return Illuminate\Auth\UserInterface|null
	*/
	public function retrieveByCredentials(array $credentials)
	{
		$result = ldap_search($this->conn, $this->config['basedn'], "(samaccountname={$credentials['username']})", $this->config['attributes']);
		if ($result === FALSE)
			return NULL;

		$entries = ldap_get_entries($this->conn, $result);
		if ($entries['count'] == 0 || $entries['count'] > 1)
			return NULL;

		return $this->clean($entries[0]);
	}

	/**
	* Validate a user against the given credentials.
	*
	* @param  Illuminate\Auth\UserInterface  $user
	* @param  array  $credentials
	* @return bool
	*/    
	public function validateCredentials(UserInterface $user, array $credentials)
	{
		if($user == NULL)
			return FALSE;
		if(isset($credentials['NTLM']))
			return TRUE;
		if($credentials['password'] == '')
			return FALSE;

		if(!$result = @ldap_bind($this->conn, $user->id, $credentials['password']))
			return FALSE;

		return TRUE;
	}

	/**
	 * Cleans the data for the LDAP model including some additional fields.
	 * @param  array  $entry 
	 * @return void        
	 */
	public function clean(array $entry)
	{
		$entry['id'] = $entry['dn'];
		$entry['remember_token'] = $entry['dn'];
		$entry['username'] = $entry['samaccountname'][0];

		// Default user type (ACL: 0 = admin, 1 = user)
		$entry['type'] = 1;
		$entry['group'] = '';

		// Group based view access check
		if(count($this->config['groups']) > 0)
		{
			$entry['type'] = NULL;
		}

		foreach ($this->config['groups'] as $group) 
		{
			$cn = 'CN='.$group.','.$this->config['groupdn'];
			if (isset($entry['dn']) 
				&& $this->checkGroup($entry['dn'], $cn))
			{
				$entry['type'] = 1;
				$entry['group'] = $group;
			}
		}
		
		// Admin Group Check
		foreach ($this->config['admin_groups'] as $group) 
		{
			$cn = 'CN='.$group.','.$this->config['groupdn'];
			if (isset($entry['dn']) 
				&& $this->checkGroup($entry['dn'], $cn))
			{
				$entry['type'] = 0;
				$entry['group'] = $group;
			}
		}

		// Admin/Owner Check (individual user owner/admins)
		foreach ($this->config['owners'] as $owner) 
		{
			if (isset($entry['samaccountname']) 
				&& $entry['samaccountname'][0] == $owner)
			{
				$entry['type'] = 0;
				$entry['group'] = '';
			}
		}

		// If View Groups exist and User is not in group
		if($entry['type'] === NULL)
			return NULL;

		$this->model = new GenericUser( $entry );

		return $this->model;
	}

	/**
	 * Checks group membership of the user, searching
	 * in the specified group and its children (recursively)
	 */
	protected function checkGroup($userdn, $groupdn) 
	{	
		$members = $this->getMembers($userdn);

		if ($members == NULL) 
			return FALSE;

		for ($i = 0; $i < $members['count']; $i++) 
		{
			if ($groupdn == $members[$i])
				return TRUE;
			elseif ($this->checkGroup($members[$i], $groupdn)) 
				return TRUE; 
		}

		return FALSE;
	}

	protected function getMembers($dn)
	{
		$result = @ldap_read($this->conn, $dn, '(objectclass=*)');
		if ($result === FALSE)
			return NULL;

		$entries = ldap_get_entries($this->conn, $result);
		if ($entries['count'] == 0)
			return NULL;

		return !empty($entries[0]['memberof']) ? $entries[0]['memberof'] : NULL;
	}

}