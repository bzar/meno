extern crate ws;
extern crate getopts;
extern crate rusqlite;
extern crate sha2;
extern crate rand;

use ws::{connect, CloseCode, listen, Message};
use getopts::Options;
use std::env;
use std::io;
use std::f64;
use std::str::FromStr;
use std::io::prelude::*;
use sha2::sha2::Sha256;
use sha2::digest::Digest;
use rand::{thread_rng, Rng};
use rand::os::OsRng;

enum Error {
    UnknownCommand(String),
    InvalidCredentials,
    InvalidToken,
    ExistingUsername,
    SyntaxError(String),
    DatabaseError(rusqlite::Error)
}

trait Digestible {
    fn digest(&self) -> String;
}

impl Digestible for str {
    fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.input_str(&self);
        hasher.result_str()
    }
}

impl Digestible for [u8] {
    fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.input(&self);
        hasher.result_str()
    }
}

fn generate_token() -> String {
    let mut rng = OsRng::new().unwrap();
    let mut bytes: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut bytes);
    bytes.digest()
}

fn create_token(user_id: &i64, db: &rusqlite::Connection) -> Result<String, Error> {
    let token = generate_token();

    let stmt = "INSERT INTO token (user_id, token) VALUES ($1, $2)";
    match db.execute(stmt, &[user_id, &token]) {
        Ok(_) => { Ok(token) }
        Err(e) => { Err(Error::DatabaseError(e)) }
    }
}

fn authenticate_token(token: &str, db: &rusqlite::Connection) -> Result<i64, Error> {
    let token_string = token.to_string();
    let stmt = "SELECT user_id FROM token WHERE token = $1";

    let mut query = db.prepare(stmt).unwrap();
    let mut results = query.query(&[&token_string]).unwrap();
    match results.next() {
        Some(Ok(row)) => { Ok(row.get::<i32, i64>(0)) }
        None => { Err(Error::InvalidToken) }
        Some(Err(x)) => { Err(Error::DatabaseError(x)) }
    }
}

fn generate_team_name() -> String {
    thread_rng().gen_ascii_chars().take(8).collect()
}

fn register(user: &str, pass: &str, db: &rusqlite::Connection) -> Result<String, Error> {
    if user.len() == 0 || pass.len() == 0 {
        return Err(Error::InvalidCredentials);
    }

    let user_string = user.to_string();
    let hash_string = pass.digest();

    let stmt = "INSERT INTO user (username, password) VALUES ($1, $2)";
    match db.execute(stmt, &[&user_string, &hash_string]) {
        Ok(_) => { Ok("Registered!".to_string()) }
        _ => { Err(Error::ExistingUsername) }
    }
}

fn login(user: &str, pass: &str, db: &rusqlite::Connection) -> Result<String, Error> {
    let user_string = user.to_string();
    let hash_string = pass.digest();

    let stmt = "SELECT id FROM user WHERE username = $1 and password = $2";
    let mut query = db.prepare(stmt).unwrap();
    let mut results = query.query(&[&user_string, &hash_string]).unwrap();
    match results.next() {
        Some(Ok(row)) => { create_token(&row.get(0), db) }
        None => { Err(Error::InvalidCredentials) }
        Some(Err(x)) => { Err(Error::DatabaseError(x)) }
    }
}

fn set_location(user_id: i64, longitude: f64, latitude: f64,
                db: &rusqlite::Connection) -> Result<String, Error> {
    let stmt = "INSERT INTO location (user_id, longitude, latitude) VALUES ($1, $2, $3)";
    match db.execute(stmt, &[&user_id, &longitude, &latitude]) {
        Ok(_) => { Ok("Location recorded".to_string()) }
        Err(e) => { Err(Error::DatabaseError(e)) }
    }
}

fn get_members(user_id: i64, teamname: &str,
                 db: &rusqlite::Connection) -> Result<String, Error> {
    let team_string = teamname.to_string();

    let team_id = {
        let member_stmt = "
            SELECT t.id FROM team t 
            JOIN team_member m on t.id = m.team_id 
            WHERE m.user_id = $1 AND teamname = $2";
        let mut member_query = db.prepare(member_stmt).unwrap();
        let mut member_results = member_query.query(&[&user_id, &team_string]).unwrap();
        try!(match member_results.next() {
            Some(Ok(row)) => { Ok(row.get::<i32, i64>(0)) }
            _ => { Err(Error::InvalidCredentials) }
        })
    };

    let stmt = "
        SELECT u.username, l.timestamp, l.longitude, l.latitude
        FROM (
            SELECT l.user_id, max(l.timestamp) as timestamp
            FROM location l
            JOIN team_member m on m.user_id = l.user_id
            WHERE m.team_id = $1
            GROUP BY l.user_id
        ) ll
        JOIN location l on (l.user_id = ll.user_id AND l.timestamp = ll.timestamp)
        JOIN user u on u.id = l.user_id";
    let mut query = db.prepare(stmt).unwrap();
    let from_row = |row: &rusqlite::Row| {
        let user: String = row.get(0);
        let timestamp: String = row.get(1);
        let longitude: f64 = row.get(2);
        let latitude: f64 = row.get(3);
        format!("{},{},{},{}", user, timestamp, longitude, latitude)
    };

    let results: Vec<String> = query.query_map(&[&team_id], from_row).unwrap()
        .map(|x| x.unwrap()).collect();

    Ok(results.join(";"))
}

fn create_team(user_id: i64, password: &str,
               db: &rusqlite::Connection) -> Result<String, Error> {
   let teamname = generate_team_name();
   let hash_string = password.digest();
   let stmt = "INSERT INTO team (teamname, password) VALUES ($1, $2)";
   try!(match db.execute(stmt, &[&teamname, &hash_string]) {
       Ok(x) => { Ok(x) }
       Err(x) => { Err(Error::DatabaseError(x)) }
   });

   try!(join_team(user_id, &teamname, &password, &db));
   Ok(teamname)
}

fn join_team(user_id: i64, teamname: &str, password: &str,
             db: &rusqlite::Connection) -> Result<String, Error> {
    let team_string = teamname.to_string();
    let hash_string = password.digest();

    let team_id = {
        let stmt = "SELECT id FROM team WHERE teamname = $1 and password = $2";
        let mut query = db.prepare(stmt).unwrap();
        let mut results = query.query(&[&team_string, &hash_string]).unwrap();
        try!(match results.next() {
            Some(Ok(row)) => { Ok(row.get::<i32, i64>(0)) }
            None => { Err(Error::InvalidCredentials) }
            Some(Err(x)) => { Err(Error::DatabaseError(x)) }
        })
    };

    let join_stmt = "INSERT INTO team_member (team_id, user_id) VALUES ($1, $2)";
    match db.execute(join_stmt, &[&team_id, &user_id]) {
        Ok(_) => { Ok("Joined!".to_string()) }
        Err(x) => { Err(Error::DatabaseError(x)) }
    }
}

fn leave_team(user_id: i64, teamname: &str,
              db: &rusqlite::Connection) -> Result<String, Error> {
    let team_string = teamname.to_string();
    let (team_id, team_size) = {
        let stmt = "
            SELECT t.id, COUNT(*)
            FROM team t
            JOIN team_member m on m.team_id = t.id
            WHERE teamname = $1";
        let mut query = db.prepare(stmt).unwrap();
        let mut results = query.query(&[&team_string]).unwrap();
        try!(match results.next() {
            Some(Ok(row)) => { Ok((row.get::<i32, i64>(0), row.get::<i32,i64>(1))) }
            None => { Err(Error::InvalidCredentials) }
            Some(Err(x)) => { Err(Error::DatabaseError(x)) }
        })
    };

    let leave_stmt = "DELETE FROM team_member WHERE team_id = $1 AND user_id = $2";
    try!(match db.execute(leave_stmt, &[&team_id, &user_id]) {
        Ok(x) => { Ok(x) }
        Err(x) => { Err(Error::DatabaseError(x)) }
    });

    if team_size == 1 {
        let delete_stmt = "DELETE FROM team WHERE id = $1";
        try!(match db.execute(delete_stmt, &[&team_id]) {
            Ok(x) => { Ok(x) }
            Err(x) => { Err(Error::DatabaseError(x)) }
        });
    } 

    Ok("Left!".to_string())
}

fn get_teams(user_id: i64, db: &rusqlite::Connection) -> Result<String, Error>  {
    let stmt = "
        SELECT t.teamname
        FROM team t
        JOIN team_member m on m.team_id = t.id
        WHERE m.user_id = $1";
    let mut query = db.prepare(stmt).unwrap();
    let from_row = |row: &rusqlite::Row| { row.get::<i32, String>(0) };
    let results: Vec<String> = query.query_map(&[&user_id], from_row).unwrap()
        .map(|x| x.unwrap()).collect();
    Ok(results.join(";"))
}

fn database_connection() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open("meno.sqlite").unwrap();
    let create_tables = "
                 CREATE TABLE IF NOT EXISTS user (
                 id       INTEGER PRIMARY KEY,
                 username VARCHAR NOT NULL UNIQUE,
                 password VARCHAR NOT NULL);

                 CREATE TABLE IF NOT EXISTS token (
                 id        INTEGER PRIMARY KEY,
                 user_id   INTEGER,
                 timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                 token     VARCHAR NOT NULL,
                 FOREIGN KEY(user_id) REFERENCES user(id));
                 
                 CREATE TABLE IF NOT EXISTS location (
                 id        INTEGER PRIMARY KEY,
                 user_id   INTEGER,
                 timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                 longitude DOUBLE NOT NULL,
                 latitude  DOUBLE NOT NULL,
                 FOREIGN KEY(user_id) REFERENCES user(id));

                 CREATE TABLE IF NOT EXISTS team (
                 id       INTEGER PRIMARY KEY,
                 teamname VARCHAR NOT NULL UNIQUE,
                 password VARCHAR NOT NULL);

                 CREATE TABLE IF NOT EXISTS team_member (
                 id       INTEGER PRIMARY KEY,
                 team_id  INTEGER NOT NULL,
                 user_id  INTEGER NOT NULL,
                 FOREIGN KEY(user_id) REFERENCES user(id),
                 FOREIGN KEY(team_id) REFERENCES team(id));
                 ";

    conn.execute_batch(create_tables).unwrap();
    return conn
}

fn parse_float(s: &str) -> Result<f64, Error> {
    match f64::from_str(s) {
        Ok(value) => { Ok(value) }
        Err(_) => { Err(Error::SyntaxError(s.to_string())) }
    }
}

fn process_message(content: String, db: &rusqlite::Connection) -> Result<String, Error> {
    let mut parts = content.split(";");
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "register" => {
            let user = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            register(&user, &pass, &db)
        }
        "login" => {
            let user = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            login(&user, &pass, &db)
        }
        "setlocation" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            let longitude = try!(parse_float(&parts.next().unwrap_or("")));
            let latitude = try!(parse_float(&parts.next().unwrap_or("")));
            set_location(user_id, longitude, latitude, &db)
        }
        "create" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            let pass = parts.next().unwrap_or("");
            create_team(user_id, &pass, &db)
        }
        "join" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            let team = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            join_team(user_id, &team, &pass, &db)
        }
        "leave" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            let team = parts.next().unwrap_or("");
            leave_team(user_id, &team, &db)
        }
        "members" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            let team = parts.next().unwrap_or("");
            get_members(user_id, &team, &db)
        }
        "teams" => {
            let user_id = try!(authenticate_token(parts.next().unwrap_or(""), &db));
            get_teams(user_id, &db)
        }
        _ => Err(Error::UnknownCommand(cmd.to_string()))
    }
}

fn server(address: &str) {
    listen(address, |out| {
        let db = database_connection();

        move |msg: Message| {
            let content = match msg {
                Message::Text(t) => { t.clone() }
                Message::Binary(_) => { "".to_string() }
            };

            let reply = match process_message(content, &db) {
                Ok(msg) => { Message::text(format!("0;{}", msg)) }
                Err(Error::ExistingUsername) => {
                    Message::text("1;Existing username")
                }
                Err(Error::InvalidCredentials) => {
                    Message::text("1;Invalid credentials")
                }
                Err(Error::InvalidToken) => {
                    Message::text("1;Invalid token")
                }
                Err(Error::DatabaseError(e)) => {
                    println!("1;Database error {:?}", e);
                    Message::text("Database error")
                }
                Err(Error::SyntaxError(s)) => {
                    Message::text(format!("1;Syntax error: {}", s))
                }
                Err(Error::UnknownCommand(cmd)) => {
                    Message::text(format!("1;Unknown command {}", cmd))
                }
            };

            out.send(reply)
        }
    }).unwrap()
}

fn client(address: &str, message: &str) {
    connect(address, |out| {
        out.send(message).unwrap();

        move |msg| {
            println!("{}", msg);
            out.close(CloseCode::Normal)
        }
    }).unwrap()
}

fn print_usage(executable: &str, opts: Options) {
    let brief = format!("Usage: {} (client|server) [options]", executable);
    println!("{}", opts.usage(&brief));
}

fn main() {
    let mut opts = Options::new();
    opts.optopt("l", "listen", "listen host:port", "HOSTPORT");
    opts.optopt("c", "connect", "server websocket URL", "URL");
    opts.optopt("m", "message", "message to send", "MESSAGE");

    let args: Vec<String> = env::args().collect();
    let executable = args[0].clone();
    if args.len() < 2 {
        print_usage(&executable, opts);
        return;
    }

    let mode = args[1].clone();

    let matches = match opts.parse(&args[2..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if mode == "client" {
        let url = matches.opt_str("c").unwrap_or("ws://127.0.0.1:3012".to_string());
        let message = matches.opt_str("m").unwrap_or("".to_string());
        if message.is_empty() {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                client(&url, &line.unwrap());
            }
        } else {
            client(&url, &message);
        }
    } else if mode == "server" {
        let hostport = match matches.opt_str("l") {
            Some(hp) => { hp }
            None => { "0.0.0.0:3012".to_string() }
        };
        server(&hostport);
    } else {
        print_usage(&executable, opts);
    }

} 
