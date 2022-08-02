<?php
//update 'session.cookie_lifetime = 604800' (7 days) on php.ini
require_once('BrowserDetection.php');
$browser = new Wolfcast\BrowserDetection();

class _account {

	private $id;
	private $username;
	private $authenticated;
	private $updateTime;

	public function __construct(){
		$this->id = NULL;
		$this->username = NULL;
		$this->authenticated = FALSE;
		$this->updateTime = NULL;
	}
	
	public function __destruct(){
		
	}

	public function login(string $username, string $password): bool {
		global $conn;
		$conn->link = $conn->connect();

		if(!empty($username) && !empty($password)){
			if($stmt = $conn->link->prepare("SELECT id, password FROM users WHERE username = ?")){
				$stmt->bind_param('s', $username);
				try{
					$stmt->execute();
					$stmt->store_result();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				if($stmt->num_rows > 0){
					$stmt->bind_result($db_account_id, $db_account_password);
					$stmt->fetch();

					if(password_verify($password, $db_account_password)){
						session_regenerate_id();

						$_SESSION['loggedin'] = TRUE;
						$_SESSION['id'] = $db_account_id;
						$_SESSION['username'] = $username;
						if(!isset($_SESSION['updateTime'])) $_SESSION['updateTime'] = strtotime('NOW');

						$this->id = $db_account_id;
						$this->username = $username;
						$this->authenticated = TRUE;
						$this->updateTime = $_SESSION['updateTime'];

						if(!$this->isActive()){
							throw new Exception(ERROR_LOGIN_DENIED);
							$this->logout();
						}

						//Verify if the current password's hash needs to be updated to newest algorithm
						if(password_needs_rehash($db_account_password, $password)){
							if($stmt = $conn->link->prepare("UPDATE users SET password = ? WHERE id = ?")){
								$stmt->bind_param('si', $new_hash, $refer_id);

								$new_hash = password_hash($password, PASSWORD_DEFAULT);
								$refer_id = $db_account_id;
								$stmt->execute();
								echo '<div class="popup popup-green">Obaa! seu hash foi atualizado para a versão mais recente!</div>';
							}
						}

						/* Register the current Sessions on the database */
						$this->registerLoginSession();

						return TRUE;
					} else{
						$stmt->close();
						$conn->disconnect($conn->link);
						throw new Exception(ERROR_LOGIN_PASSWORD);
					}
				} else{
					$stmt->close();
					$conn->disconnect($conn->link);
					throw new Exception(ERROR_LOGIN_USERNAME);
				}
			}
		} else {
			throw new Exception(ERROR_LOGIN_BLANK);
		}
	}

	private function registerLoginSession(){
		global $conn;
		global $browser;
		$conn->link = $conn->connect();

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("REPLACE INTO users_sessions (session_id, user_id, login_time, user_agent, user_OS) VALUES (?, ?, NOW(), ?, ?)")){
				$stmt->bind_param('siss', $session, $userid, $user_agent, $user_OS);
				$session = session_id();
				$userid = $this->id;
				$user_agent = $_SERVER['HTTP_USER_AGENT'];
				$user_OS = $browser->getPlatform() .' '. $browser->getPlatformVersion(true);

				/*
				$browser->setUserAgent($user_agent);

				echo $browser->getName();
				echo $browser->getVersion();
				echo $browser->getPlatform();
				echo $browser->getPlatformVersion(true);
				*/

				try{
					$stmt->execute();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				$stmt->close();
				$conn->disconnect($conn->link);
				return TRUE;
			}
		}
	}

	public function regenerateSession($userid): bool{
		global $conn;
		$conn->link = $conn->connect();

		if($stmt = $conn->link->prepare("UPDATE users_sessions SET users_sessions.session_id = ? WHERE users_sessions.session_id = ? AND users_sessions.user_id = ?")){
			$stmt->bind_param('ssi', $newSession, $actualSession, $userid);
			$actualSession = session_id();
			session_regenerate_id();
			$newSession = session_id();

			try{
				$stmt->execute();
			}
			catch(Exception $e){
				throw new Exception('Erro ao conectar com a base de dados: '. $e);
			}
			$stmt->close();
			$conn->disconnect($conn->link);
			return TRUE;
		}
		$stmt->close();
		$conn->disconnect($conn->link);
		return FALSE;
	}

	//Workaround when mysqlnd not working
	function get_result($statement){
		$RESULT = array();
		$statement->store_result();
		for ($i=0; $i<$statement->num_rows; $i++) {
			$Metadata = $statement->result_metadata();
			$PARAMS = array();
			while ($field = $Metadata->fetch_field()){
				$PARAMS[] = &$RESULT[$i][$field->name];
			}
			call_user_func_array( array( $statement, 'bind_result' ), $PARAMS );
			$statement->fetch();
		}
		return $RESULT;
	}

	public function sessionLogin(): bool{ //It is called in every page that needs auth
		global $conn;
		$conn->link = $conn->connect();

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("SELECT * FROM users_sessions, users WHERE (users_sessions.session_id = ?) AND (users_sessions.login_time >= (NOW() - INTERVAL 7 DAY)) AND (users_sessions.user_id = users.id) AND (users.active = 1)")){
				$stmt->bind_param('s', $session);
				$session = session_id();

				try{
					$stmt->execute();
					//$result = $stmt->get_result();
					$result = $this->get_result($stmt);
					//$data = $result->fetch_all(MYSQLI_ASSOC);
					$row = array_shift($result);
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				if($stmt->num_rows > 0){

					$this->id = $row['id'];
					$this->username = $row['username'];
					$this->authenticated = TRUE;
					$this->updateTime = $_SESSION['updateTime'];

					$differenceBetweenTimes = (strtotime('NOW') - $this->updateTime);
					$minutesToUpdate = $differenceBetweenTimes / 60;

					if($minutesToUpdate > 30){
						//Updates the session id X minutes
						if(!$this->regenerateSession($this->id)){
							$this->logout();
						}
						$_SESSION['updateTime'] = strtotime('NOW');
					}					
					return TRUE;
				} else if($this->getFileName() == 'cpanel.php'){
					//Do nothing, the user is on the homepage
				} else{
					$this->logout();
				}
				$stmt->close();
				$conn->disconnect($conn->link);
			}
			$this->logout();
		}
		return FALSE;
	}

	public function getFileName(): string {
		$arr = $_SERVER['SCRIPT_NAME'];
		$arr = explode('/', $arr);
		$arr_max = count($arr);
		array_splice($arr, 0, $arr_max-1);
		
		return $arr[0];
	}

	public function isAuthenticated(): bool {
		return $this->authenticated;
	}

	public function isActive(): bool{
		global $conn;
		$conn->link = $conn->connect();

		if($stmt = $conn->link->prepare("SELECT active FROM users WHERE id = ?")){
			$stmt->bind_param('i', $this->id);

			try{
				$stmt->execute();
				$stmt->store_result();
				$stmt->bind_result($user_active);
				$stmt->fetch();
			}
			catch(Exception $e){
				throw new Exception('Error Processing Request: '. $e);
			}
			return $user_active;
		}
		return FALSE;
	}

	public function myId(){
		return $this->id;
	}

	public function logout(){
		global $conn;
		$conn->link = $conn->connect();

		if(is_null($this->id) && ($this->getFileName() == 'cpanel.php')){
			return;
		}

		$this->id = NULL;
		$this->username = NULL;
		$this->authenticated = FALSE;

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("DELETE FROM users_sessions WHERE session_id = ?")){
				$stmt->bind_param('s', $session_id);
				$session_id = session_id();

				try{
					$stmt->execute();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				session_unset();
				session_destroy();

				$stmt->close();
				$conn->disconnect($conn->link);
			}
			echo '<script>window.location = "./cpanel?return='.($this->getFileName()).'";</script>';
		} else {
			session_unset();
			session_destroy();

			echo '<script>window.location = "./cpanel?return='.($this->getFileName()).'";</script>';
		}
		echo '<script>window.location = "./cpanel?return='.($this->getFileName()).'";</script>';
	}

	public function closeThisSession($session_number){
		global $conn;		
		$conn->link = $conn->connect();

		if(is_null($this->id)){
			return;
		}

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("DELETE FROM users_sessions WHERE session_number = ? AND user_id = ?")){
				$stmt->bind_param('si', $session_number, $user_id);
				$user_id = $this->id;

				try{
					$stmt->execute();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
					die();
				}
				$stmt->close();
				$conn->close($conn->link);
			}
		}
		return TRUE;
	}

	public function closeOtherSessions(){
		global $conn;		
		$conn->link = $conn->connect();

		if(is_null($this->id)){
			return;
		}

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("DELETE FROM users_sessions WHERE session_id != ? AND user_id = ?")){
				$stmt->bind_param('si', $session_id, $user_id);
				$session_id = session_id();
				$user_id = $this->id;

				try{
					$stmt->execute();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				//session_unset();
				//session_destroy();
				$stmt->close();
				$conn->disconnect($conn->link);
			}
		}
		return TRUE;
	}

	public function closeAllSessionsFrom($id){
		global $conn;		
		$conn->link = $conn->connect();
		$id = stripslashes($id);

		if(is_null($this->id)){
			return;
		}

		if(session_status() == PHP_SESSION_ACTIVE){
			if($stmt = $conn->link->prepare("DELETE FROM users_sessions WHERE user_id = ?")){
				$stmt->bind_param('i', $id);

				try{
					$stmt->execute();
				}
				catch(Exception $e){
					throw new Exception('Erro ao conectar com a base de dados: '. $e);
				}
				//session_unset();
				//session_destroy();
				$stmt->close();
				$conn->disconnect($conn->link);
			}
		}
		return TRUE;
	}

	public function addUser(string $username, string $name, string $email, string $password, string $permissions, string $active): bool {
		global $conn;
		$conn->link = $conn->connect();

		if($stmt = $conn->link->prepare("INSERT INTO users (username, name, email, password, permissions, active) VALUES (?, ?, ?, ?, ?, ?)")){
			$stmt->bind_param('ssssii', $username, $name, $email, $hash, $permissions, $active);

			$username = stripslashes($username);

			$name = stripslashes($name);

			$email = stripslashes($email);

			$password = stripslashes($password);
			$hash = password_hash($password, PASSWORD_DEFAULT);

			$permissions = stripslashes($permissions);

			$active = stripslashes($active);

			if(!$this->isNameValid($username)){
				throw new Exception(INVALID_USERNAME);
				return FALSE;
			}
			if(!$this->userExists($username)){
				throw new Exception(USERNAME_EXISTS);
				return FALSE;
			}
			if(!$this->isPasswordValid($password)){
				throw new Exception(INVALID_PASSWORD);
				return FALSE;
			}
			try{
				$stmt->execute();
				
			}
			catch(Exception $e){
				throw new Exception('Erro ao conectar com a base de dados: '. $e);
			}
			$stmt->close();
			$conn->disconnect($conn->link);
			return TRUE;
		}
		$stmt->close();
		$conn->disconnect($conn->link);
	}

	public function changePassword(string $id, string $password): bool {
		global $conn;
		$conn->link = $conn->connect();

		if($stmt = $conn->link->prepare("UPDATE users SET password = ? WHERE id = ?")){
			$stmt->bind_param('si', $hash, $id);

			$id = stripslashes($id);

			$password = stripslashes($password);
			$hash = password_hash($password, PASSWORD_DEFAULT);

			try{
				$stmt->execute();
				
			}
			catch(Exception $e){
				throw new Exception('Erro ao conectar com a base de dados: '. $e);
			}
			$stmt->close();
			$conn->disconnect($conn->link);
			return TRUE;
		}
		$stmt->close();
		$conn->disconnect($conn->link);
	}

	public function rmvUser(string $username, string $user_id): bool {
		global $conn;
		$conn->link = $conn->connect();

		$username = stripslashes($username);
		$username = mysqli_real_escape_string($conn->link, $username);

		$user_id = stripslashes($user_id);
		$user_id = mysqli_real_escape_string($conn->link, $user_id);
		if($stmt = $conn->link->prepare("DELETE FROM users WHERE username = ? AND id = ?")){
			$stmt->bind_param('si', $username, $user_id);

			try{
				$stmt->execute();
			}
			catch(Exception $e){
				throw new Exception('Erro ao conectar com a base de dados: '. $e);
			}
			return TRUE;
		}
		return FALSE;
	}

	public function isNameValid(string $username): bool {
		/* Initialize the return variable */
		$valid = TRUE;
		
		/* Length must be between 4 and 20 chars */
		$len = mb_strlen($username);
		
		if (($len < 4) || ($len > 20))
		{
			$valid = FALSE;
		}
		
		return $valid;
	}

	public function isPasswordValid(string $password): bool {
		/* Initialize the return variable */
		$valid = TRUE;
		
		/* Length must be between 6 */
		$len = mb_strlen($password);
		
		if (($len < 6))
		{
			$valid = FALSE;
		}
		
		return $valid;
	}

	public function userExists(string $username): bool {
		global $conn;
		$link = $conn->connect();

		$isValid = TRUE;

		if($stmt = $link->prepare("SELECT username FROM users WHERE username = ?")){
			$stmt->bind_param('s', $username);

			try{
				$stmt->execute();
				$stmt->store_result();
			}
			catch(Exception $e){
				throw new Exception('Erro ao conectar com a base de dados: '. $e);
			}

			if($stmt->num_rows > 0){
				$isValid = FALSE;
			}
			return $isValid;
		}
	}
}
$account = new _account();
?>