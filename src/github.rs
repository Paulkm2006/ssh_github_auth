use reqwest::blocking::Client;
use serde::{self, Deserialize};

#[derive(Debug, Deserialize)]
pub struct GithubUser {
	pub state: GithubState,
	pub role: GithubRole,
	#[serde(skip_deserializing)]
	org: String,
	#[serde(skip_deserializing)]
	pat: String,
	#[serde(skip_deserializing)]
	pub username: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubState {
	Pending,
	Active,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubRole {
	Member,
	Admin,
	#[serde(rename = "billing_manager")]
	Billing,
}

#[derive(Debug)]
pub enum GithubError {
	NotFound,
	Unauthorized,
	Forbidden,
	InvalidUser(String),
	Other(String),
}

impl GithubUser {

	pub fn from_device_code(
		device_code: &str,
		client_id: &str,
		username: &str,
		org: &str,
	) -> Result<Self, GithubError> {
		let client = Client::new();
		let response = client
			.post("https://github.com/login/oauth/access_token")
			.header("Accept", "application/json")
			.form(&[
				("client_id", client_id),
				("device_code", device_code),
				("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
			])
			.send();
		if response.is_err() {
			return Err(GithubError::Other(
				format!("Failed to send request for access token: {}", response.err().unwrap()),
			));
		}
		let response = response.unwrap();
		if response.status().is_success() {
			let auth_code: serde_json::Value = response.json().unwrap();
			let access_token = match auth_code["access_token"].as_str(){
				Some(token) => token.to_string(),
				None => {
					return Err(GithubError::Unauthorized);
				}
			};
			if let Err(e) = check_username(username, &access_token) {
				return Err(e);
			}

			Self::from_pat(&access_token, username, org)
		} else if response.status().as_u16() == 401 {
			Err(GithubError::Unauthorized)
		} else if response.status().as_u16() == 403 {
			Err(GithubError::Forbidden)
		} else {
			Err(GithubError::Other(
				format!("Unexpected error at device code: {}", response.status()),
			))
		}
	}

	pub fn from_pat(pat: &str, username: &str, org: &str) -> Result<Self, GithubError> {
		let client = Client::new();
		let url = format!("https://api.github.com/orgs/{}/memberships/{}", org, username);
		let response = client
			.get(&url)
			.header("Accept", "application/json")
			.header("Authorization", format!("Bearer {}", pat))
			.header("User-Agent", "ssh-with-gh")
			.send();
		if response.is_err() {
			return Err(GithubError::Other(
				format!("Failed to send request for memberships: {}", response.err().unwrap()),
			));
		}
		let response = response.unwrap();
		let status = response.status().as_u16();
		let text = response.text().unwrap();
		if status == 200 {
			let mut user: GithubUser = serde_json::from_str(&text).unwrap();
			user.org = org.to_string();
			user.pat = pat.to_string();
			user.username = username.to_string();
			Ok(user)
		} else if status == 404 {
			Err(GithubError::NotFound)
		} else if status == 401 {
			Err(GithubError::Unauthorized)
		} else if status == 403 {
			Err(GithubError::Forbidden)
		} else {
			Err(GithubError::Other(
				format!("Unexpected error at pat: {}", text),
			))
			
		}
	}

	pub fn is_in_team(&self, team: &str) -> Result<bool, reqwest::Error> {
		let client = Client::new();
		let url = format!(
			"https://api.github.com/orgs/{}/teams/{}/memberships/{}",
			self.org, team, self.username
		);
		let response = client
			.get(&url)
			.header("Authorization", format!("Bearer {}", self.pat))
			.send()?;
		if response.status().is_success() {
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub fn get_keys(&self) -> Result<String, GithubError> {
		let client = Client::new();
		let url = format!("https://github.com/{}.keys", self.username);
		let response = client
			.get(&url)
			.header("User-Agent", "ssh-with-gh")
			.send();
		if response.is_err() {
			return Err(GithubError::Other(
				format!("Failed to send request for keys: {}", response.err().unwrap()),
			));
		}
		let response = response.unwrap();
		if response.status().is_success() {
			Ok(response.text().unwrap())
		} else if response.status().as_u16() == 404 {
			Err(GithubError::NotFound)
		} else if response.status().as_u16() == 401 {
			Err(GithubError::Unauthorized)
		} else if response.status().as_u16() == 403 {
			Err(GithubError::Forbidden)
		} else {
			Err(GithubError::Other(
				format!("Unexpected error at keys: {}", response.status()),
			))
			
		}
	}
}



pub fn get_auth_code(client_id: &str) -> Result<(String, String), GithubError> {
	let client = Client::new();
	let response = client
		.post("https://github.com/login/device/code")
		.header("Accept", "application/json")
		.form(&[("client_id", client_id)])
		.send();
	if response.is_err() {
		return Err(GithubError::Other(
			format!("Failed to send request for device code: {}", response.err().unwrap()),
		));
	}
	let response = response.unwrap();
	if response.status().is_success() {
		let auth_code: serde_json::Value = response.json().unwrap();
		let device_code = auth_code["device_code"].as_str().unwrap().to_string();
		let user_code = auth_code["user_code"].as_str().unwrap().to_string();
		Ok((device_code, user_code))
	} else if response.status().as_u16() == 401 {
		Err(GithubError::Unauthorized)
	} else if response.status().as_u16() == 403 {
		Err(GithubError::Forbidden)
	} else {
		Err(GithubError::Other(
			format!("Unexpected error: {}", response.status()),
		))
	}
}

fn check_username(username: &str, pat: &str) -> Result<(), GithubError> {
	let client = Client::new();
	let response = client
		.get("https://api.github.com/user")
		.header("Accept", "application/json")
		.header("Authorization", format!("Bearer {}", pat))
		.header("User-Agent", "ssh-with-gh")
		.send();
	if response.is_err() {
		return Err(GithubError::Other(
			format!("Failed to send request for user info: {}", response.err().unwrap()),
		));
	}
	let response = response.unwrap();
	if response.status().is_success() {
		let user: serde_json::Value = response.json().unwrap();
		let login = user["login"].as_str().unwrap().to_ascii_lowercase();
		if login == username {
			Ok(())
		} else {
			Err(GithubError::InvalidUser(
				format!("Username does not match: {} != {}", username, login),
			))
		}
	} else if response.status().as_u16() == 401 {
		Err(GithubError::Unauthorized)
	} else if response.status().as_u16() == 403 {
		Err(GithubError::Forbidden)
	} else {
		Err(GithubError::Other(
			format!("Unexpected error at username: {}", response.status()),
		))
	}
}