//! This crate provides an API on top of [TinyTinyRSS](https://tt-rss.org/)
//! ## Usage
//! 
//! Add this to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! ttrss_api = "0.0.1"
//! ```
//! 
//! Then add this to your crate:
//! 
//! ```rust
//! extern crate ttrss_api;
//! ```
//! 
//! To use:
//! 
//! ```ignore
//! fn main() {
//!     let apilevel: Option<ApiLevel> = match get_api_level().expect("Failed to get response").content {
//!         Content::GetApiLevel(x) => { Some(x) },
//!         _ => None,
//!     };
//!     println!("api level {:?}", apilevel.unwrap());
//! ```
//! 
extern crate chrono;
extern crate strum;
extern crate serde;
extern crate serde_json;
extern crate strum_macros;

use std::env;
use std::collections::HashMap;
use std::fmt;

use chrono::serde::ts_seconds;
use chrono::prelude::*;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use strum_macros::Display;


/// Environment variable name for the API to TinyTinyRSS (TTRSS). 
static ENVVAR_TTRSS_URL: &str = "TTRSS_API_URL";
/// Environment variable name for the user id to login to the TTRSS instance
static ENVVAR_TTRSS_USERID: &str = "TTRSS_USERID";
/// Environment variable name for the user id's password to login to the TTRSS instance
static ENVVAR_TTRSS_PASSWORD: &str = "TTRSS_PASSWORD";

/// Requests to the API will timeout after this many seconds
static TIMEOUT: u64 = 20;

/// placeholder for the session_id for TTRSS API queries. This package will automatically login and populate the session ID per whether each API call requires a session ID or not
static mut SESSION_ID: Option<String> = None;


/// Result object returned from all API calls.
type ResponseResult = std::result::Result<Response, TTRSSAPIError>;


/// Used in getCounters
pub enum CounterType {
    Feeds,
    Labels,
    Categories,
    Tags,
}

impl std::fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", match self {
            CounterType::Feeds => "f",
            CounterType::Labels => "l",
            CounterType::Categories => "c",
            CounterType::Tags => "t",
        })
    }
}


/// used in get_headlines to filter describe how to filter headlines
pub enum ViewMode {
    Adaptive,
    AllArticles,
    Marked,
    Unread,
    Updated,
}

impl std::fmt::Display for ViewMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", match self {
            ViewMode::Adaptive => "adaptive",
            ViewMode::AllArticles => "all_articles",
            ViewMode::Marked => "marked",
            ViewMode::Unread => "unread",
            ViewMode::Updated => "updated",
        })
    }
}

/// Used in update_article to describe the mode
pub enum UpdateMode {
    False,
    True,
    Toggle,
}

impl std::fmt::Display for UpdateMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", match self {
            UpdateMode::False => 0,
            UpdateMode::True => 1,
            UpdateMode::Toggle => 2,
        })
    }
}


/// Used in update_article to describe which field to update
pub enum UpdateArticleField {
    Starred,
    Published,
    Unread,
    Note,
}

impl std::fmt::Display for UpdateArticleField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", match self {
            UpdateArticleField::Starred => 0,
            UpdateArticleField::Published => 1,
            UpdateArticleField::Unread => 2,
            UpdateArticleField::Note => 3,
        })
    }
}

/// Counter
/// 
/// # Rust
/// * get_counters
/// 
/// # TTRSS
/// * getCounters
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Counter {
    pub auxcounter: Option<i64>,
    pub counter: Option<i64>,
    pub has_img: Option<i64>,
    pub updated: Option<String>,
    pub markedcounter: Option<i64>,
    pub kind: Option<String>,
    pub error: Option<String>,
    pub id: Value,
}


/// Feed
/// 
/// # Rust
/// * get_feeds
/// 
/// # TTRSS
/// * getFeeds
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Feed {
    pub feed_url: String,
    pub title: String,
    pub id: u32,
    pub unread: u32,
    pub has_icon: bool,
    pub cat_id: i32,
    pub order_id: u32,

    #[serde(with = "ts_seconds")]
    pub last_updated: DateTime<Utc>,
}

/// Attachment
/// 
/// # Rust
/// * get_headlines (indirectly)
/// * get_article (indirectly)
/// 
/// # TTRSS
/// * getHeadlines (indirectly)
/// * getArticle (indirectly)
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Attachment {
    pub id: Value,
    pub content_url: String,
    pub content_type: String,
    pub title: String,
    pub duration: String,
    pub width: i64,
    pub height: i64,
    pub post_id: i64,

    /// Additional fields not specifically deefined in the struct
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Single Headline
/// 
/// # Rust
/// * get_headlines (indirectly)
/// * get_article (indirectly)
/// 
/// # TTRSS
/// * getHeadlines (indirectly)
/// * get_article (indirectly)
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Headline {
    pub id: Value,
    pub guid: String,
    pub unread: bool,
    pub marked: bool,
    pub published: bool,

    #[serde(with = "ts_seconds")]
    pub updated: DateTime<Utc>,
    pub is_updated: Option<bool>,
    pub comments: Option<String>,
    pub title: String,
    pub link: String,
    pub tags: Option<Vec<String>>,
    pub attachments: Option<Vec<Attachment>>,
    pub excerpt: Option<String>,
    pub content: Option<String>,
    pub labels: Option<Vec<String>>,
    pub feed_title: String,
    pub comments_count: Option<i64>,
    pub comments_link: Option<String>,
    pub always_display_attachments: Option<bool>,
    pub author: String,
    pub score: i64,
    pub note: Option<String>,
    pub lang: String,
    pub feed_id: Option<i64>,
    pub flavor_image: Option<String>,
    pub flavor_stream: Option<String>,

    /// Additional fields not specifically deefined in the struct
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

}

/// Wraps some metadata around the headlines from get_headlines
/// 
/// # Rust
/// * get_headlines (indirectly)
/// 
/// # TTRSS
/// * getHeadlines (indirectly)
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct HeadlineWrapper {
    pub id: Value,
    pub first_id: Value,
    pub is_cat: bool,
    pub headlines: Vec<Headline>,

}

/// Categories
/// 
/// # Rust
/// * get_categories
/// 
/// # TTRSS
/// * getCategories
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Category {
    pub id: i64,
    pub title: String,
    pub unread: i64,
    pub order_id: Option<i64>,
}


/// Labels
/// 
/// # Rust
/// * get_labels
/// 
/// # TTRSS
/// * getLabels
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Label {
    pub id: i64,
    pub caption: String,
    pub fg_color: String,
    pub bg_color: String,
    pub checked: bool,
}

/// Feed Tree
/// 
/// # Rust
/// * get_feed_tree
/// 
/// # TTRSS
/// * getFeedTree
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct FeedTree {
    pub categories: FeedTreeCategory,
}

/// Feed Tree Category wraps metadata around lower level feed tree items
/// 
/// # Rust
/// * get_feed_tree (indirectly)
/// 
/// # TTRSS
/// * getFeedTre (indirectly)
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct FeedTreeCategory {
    pub identifier: String,
    pub label: String,
    pub items: Option<Vec<FeedTreeItem>>,
}

/// Feed Tree Item wraps represents the lowest level of item detail, although may contain child items
/// 
/// # Rust
/// * get_feed_tree (indirectly)
/// 
/// # TTRSS
/// * getFeedTree (indirectly)
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct FeedTreeItem {
    pub items: Option<Vec<FeedTreeItem>>,
    pub id: String,
    pub name: String,
    pub unread: i64,
    pub error: Option<String>,
    pub updated: Option<String>,
    pub bare_id: i64,
    pub auxcounter: Option<i64>,
    pub checkbox: Option<bool>,
    pub child_unread: Option<i64>,
    pub param: Option<String>,
    pub updates_disabled: Option<i64>,
    pub icon: Option<Value>,

    /// type is a reserved keyword in rust, so aliasing type to itype
    #[serde(rename = "type")]
    pub itype: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Login
/// 
/// # Rust
/// * login
/// 
/// # TTRSS
/// * login
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Login {
    pub session_id: String,
    pub api_level: u8
}


/// API Level
/// 
/// # Rust
/// * get_api_level
/// 
/// # TTRSS
/// * getApiLevel
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct ApiLevel {
    pub level: u8,
}


/// Version
/// 
/// # Rust
/// * get_version
/// 
/// # TTRSS
/// * getVersion
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Version {
    pub version: String,
}

/// Error response returned from API
/// 
/// # Rust
/// * any that return an error from the API call
/// 
/// # TTRSS
/// * any that return an error from the API call
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct ApiError {
    pub error: String,
}




/// Logged In
/// 
/// # Rust
/// * is_logged_in
/// 
/// # TTRSS
/// * isLoggedIn
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct LoggedIn {
    pub status: bool,
}

/// Status
/// 
/// # Rust
/// * Used in many return types that update data
/// 
/// # TTRSS
/// * Used in many return types that update data
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Status {
    pub status: String,
    pub updated: Option<i64>,
}


/// Unread
/// 
/// # Rust
/// * get_unread
/// 
/// # TTRSS
/// * getUnread
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Unread {
    pub unread: u64,
}

/// Config
/// 
/// # Rust
/// * get_config
/// 
/// # TTRSS
/// * getConfig
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Config {
    pub icons_dir: String,
    pub icons_url: String,
    pub daemon_is_running: bool,
    pub num_feeds: i64,
}


/// Preference
/// 
/// # Rust
/// * get_pref
/// 
/// # TTRSS
/// * getPref
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Preference {
    pub value: Value,
}


/// Represents the various types of responese from the TTRSS API. The user is expected to inspect the enum for the appropriate type.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Display)]
#[serde(untagged)]
pub enum Content {
    Login(Login),
    GetApiLevel(ApiLevel),
    GetVersion(Version),
    Error(ApiError),
    IsLoggedIn(LoggedIn),
    Status(Status),
    GetUnread(Unread),
    GetFeeds(Vec<Feed>),
    GetHeadlines(Vec<HeadlineWrapper>),
    Labels(Vec<Label>),
    GetArticle(Vec<Headline>),
    GetConfig(Config),
    GetPref(Preference),
    FeedTree(FeedTree),

    // getCategories and GetCounters should be at the end, in this order. As they're more generic, serde tends to use them more often
    GetCategories(Vec<Category>),
    GetCounters(Vec<Counter>),
}


/// TTRSS responses are wrapped around a seq and status, with the details per the API call within the `content` field. This object represents that wrapper.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    pub seq: Option<u8>,
    pub status: u8,
    pub content: Content,
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sequence: {}, ttrss status: {}, content: {}", self.seq.unwrap(), self.status, self.content)
    }
}


#[derive(Debug)]
pub enum TTRSSAPIError {
    SerdeError(serde_json::error::Error),
    ReqwestError(reqwest::Error),
    EnvVarError(std::env::VarError),
    InvalidRequest(String),
}

impl fmt::Display for TTRSSAPIError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &TTRSSAPIError::SerdeError(ref e) => e.fmt(formatter),
            &TTRSSAPIError::ReqwestError(ref e) => e.fmt(formatter),
            &TTRSSAPIError::EnvVarError(ref e) => e.fmt(formatter),
            &TTRSSAPIError::InvalidRequest(ref e) => formatter.write_str(&format!("Invalid request with message: {}", e))
        }
    }
}

impl From<serde_json::error::Error> for TTRSSAPIError {
    fn from(err: serde_json::error::Error) -> TTRSSAPIError {
        TTRSSAPIError::SerdeError(err)
    }
}

impl From<std::env::VarError> for TTRSSAPIError {
    fn from(err: std::env::VarError) -> TTRSSAPIError {
        TTRSSAPIError::EnvVarError(err)
    }
}

impl From<reqwest::Error> for TTRSSAPIError {
    fn from(err: reqwest::Error) -> TTRSSAPIError {
        TTRSSAPIError::ReqwestError(err)
    }
}


/// Logout of the session.
pub fn logout() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "logout".to_string());

    unsafe {
        if SESSION_ID.is_some() {
            postdata.insert("sid", populate_session_id());
            match request_from_api(postdata) {
                Ok(x) => {
                    SESSION_ID = None;
                    Ok(x)
                },
                Err(x) => Err(x),
            }
        } else {
            postdata.insert("sid", "".to_string());
            request_from_api(postdata)
        }
    }
}

/// Is the session ID logged in?
pub fn is_logged_in(session_id: String) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "isLoggedIn".to_string());
    postdata.insert("sid", session_id);
    request_from_api(postdata)
}


/// Return one preference value.
pub fn get_pref(pref_name: String) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getPref".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("pref_name", pref_name);
    request_from_api(postdata)
}


/// Get article ID's contents.
pub fn get_article(article_id: i64) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getArticle".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("article_id", article_id.to_string());
    request_from_api(postdata)
}


/// Get list of categories.
pub fn get_categories(unread_only: bool, enable_nested: bool, include_empty: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getCategories".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("unread_only", unread_only.to_string());
    postdata.insert("enable_nested", enable_nested.to_string());
    postdata.insert("include_empty", include_empty.to_string());
    request_from_api(postdata)
}


/// Get list of headlines.
pub fn get_headlines(feed_id: i64, limit: i64, skip: i64, filter: String, is_cat: bool, show_excerpt: bool, show_content: bool, view_mode: ViewMode, include_attachments: bool, since_id: i64, include_nested: bool, order_by: String, sanitize: bool, force_update: bool, has_sandbox: bool, include_header: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getHeadlines".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("feed_id", feed_id.to_string());
    postdata.insert("limit", limit.to_string());
    postdata.insert("skip", skip.to_string());
    postdata.insert("filter", filter);
    postdata.insert("is_cat", is_cat.to_string());
    postdata.insert("show_excerpt", show_excerpt.to_string());
    postdata.insert("show_content", show_content.to_string());
    postdata.insert("view_mode", view_mode.to_string());
    postdata.insert("include_attachments", include_attachments.to_string());
    postdata.insert("since_id", since_id.to_string());
    postdata.insert("include_nested", include_nested.to_string());
    postdata.insert("order_by", order_by.to_string());
    postdata.insert("sanitize", sanitize.to_string());
    postdata.insert("force_update", force_update.to_string());
    postdata.insert("has_sandbox", has_sandbox.to_string());
    postdata.insert("include_header", include_header.to_string());
    request_from_api(postdata)
}


/// Get list of feeds.
pub fn get_feeds(cat_id: i32, unread_only: bool, limit: u8, offset: u32, include_nested: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getFeeds".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("cat_id", cat_id.to_string());
    postdata.insert("unread_only", unread_only.to_string());
    postdata.insert("limit", limit.to_string());
    postdata.insert("offset", offset.to_string());
    postdata.insert("include_nested", include_nested.to_string());
    request_from_api(postdata)
}


/// Update an article.
pub fn update_article(article_ids: Vec<i64>, mode: UpdateMode, field: UpdateArticleField, data: String) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "updateArticle".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("data", data);
    postdata.insert("article_ids", article_ids.iter().map(|s| s.to_string()).collect::<Vec<String>>().join(","));
    postdata.insert("field", field.to_string());
    postdata.insert("mode", mode.to_string());
    request_from_api(postdata)
}


/// Get counters.
pub fn get_counters(counter_type: Vec<CounterType>) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getCounters".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("output_mode", counter_type.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(""));
    request_from_api(postdata)
}


/// Set an article's label.
pub fn set_article_label(article_ids: Vec<i64>, label_id: i64, assign: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "setArticleLabel".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("article_ids", article_ids.iter().map(|s| s.to_string()).collect::<Vec<String>>().join(","));
    postdata.insert("label_id", label_id.to_string());
    postdata.insert("assign", assign.to_string());
    request_from_api(postdata)
}


/// Get all labels.
pub fn get_labels() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getLabels".to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Get API version.
pub fn get_version() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getVersion".to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Catchup feed.
pub fn catchup_feed(feed_id: i64, is_cat: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "updateFeed".to_string());
    postdata.insert("feed_id", feed_id.to_string());
    postdata.insert("is_cat", is_cat.to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Update the feed.
pub fn update_feed(feed_id: i64) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "updateFeed".to_string());
    postdata.insert("feed_id", feed_id.to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Subscribe to a feed.
pub fn subscribe_to_feed(feed_url: String, category_id: i64, login: String, password: String) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "subscribeToFeed".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("feed_url", feed_url);
    postdata.insert("category_id", category_id.to_string());
    postdata.insert("login", login);
    postdata.insert("password", password);
    request_from_api(postdata)
}


/// Unsubscribe to a feed.
pub fn unsubscribe_feed(feed_id: i64) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "unsubscribeFeed".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("feed_id", feed_id.to_string());
    request_from_api(postdata)
}


/// Create tree of all feeds' and related info.
pub fn get_feed_tree(include_empty: bool) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getFeedTree".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("include_empty", include_empty.to_string());
    request_from_api(postdata)
}


/// Share information to published feed.
pub fn share_to_published(title: String, url: String, content: String) -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "shareToPublished".to_string());
    postdata.insert("sid", populate_session_id());
    postdata.insert("title", title);
    postdata.insert("url", url);
    postdata.insert("content", content);
    request_from_api(postdata)
}


/// Get configruration.
pub fn get_config() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getConfig".to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Get unread feeds.
pub fn get_unread() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getUnread".to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Get API level.
pub fn get_api_level() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    postdata.insert("op", "getApiLevel".to_string());
    postdata.insert("sid", populate_session_id());
    request_from_api(postdata)
}


/// Helper method to get the session ID from a supposedly login response
fn get_session_id_from_login(login: ResponseResult) -> Option<String> {
    match login {
        Ok(response) => {
            match response.content {
                Content::Login(x) => { Some(x.session_id) },
                _ => None,
            }
        },
        Err(_) => { None },
    }

}


/// Login to TTRSS. This will automatically happen if the API call requires a session ID
pub fn login() -> ResponseResult {
    let mut postdata: HashMap<&str, String> = HashMap::new();
    let (user, password): (&str, &str) = (&env::var(ENVVAR_TTRSS_USERID)?, &env::var(ENVVAR_TTRSS_PASSWORD)?);
    postdata.insert("op", "login".to_string());
    postdata.insert("user", user.to_string());
    postdata.insert("password", password.to_string());
    request_from_api(postdata)
}


/// Internal call to generalize communication to TTRSS' API among multiple API calls
fn request_from_api(postdata: HashMap<&str, String>) -> ResponseResult {
    validate_or_panic();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT))
        .build()?;
    //let clients = reqwest::blocking::ClientB
//    .timeout(Duration::from_secs(10))
    let response = client.post(&env::var(ENVVAR_TTRSS_URL)?)
        .json(&postdata)
        .send()?;
    
    if response.status().is_success() {
        let mut resp = response.text()?;
        if postdata.contains_key("op") && postdata.get("op").unwrap() == "getHeadlines" {
            // reasoning for this: getHeadlines sends this:
            // "{"seq":0,"status":0,"content":[{"id":100,"first_id":406482,"is_cat":false},[{"id":406482,"guid":"SHA1:bcf72e224fecc236174c682ff865fbaf1bd3d2d0","unread":true,"marked":false,"published":false,"updated":1589028361,"is_updated":false,"title":"..." ....
            // Note that the [] which contains headline data doesn't have a key. serde_json doesn't flatten sequences (Vec), just maps and objects that map to their Value struct (vec isn't one of them), so I need to put a key in there
            resp = resp.replacen("},[{", ",\"headlines\":[{", 1);
            resp = resp.replacen("}]]}", "}]}]}", 1);
            //                              ^ this 2nd { is added to close out the } removed from the first `replacen` which adds 'headlines'
        }

        //std::fs::write("/tmp/oo.txt", &resp).expect("bad");
        //println!("{}", serde_json::to_string_pretty(&resp.replace("\\", "")).unwrap_or_default());
        Ok(serde_json::from_str(&resp)?)
    } else {
        Err(TTRSSAPIError::InvalidRequest(format!("response status: {:?}", response.status())))
    }
}


/// Internal method to validate environment variables are set
fn validate_environment_variables() -> bool {
    env::var(ENVVAR_TTRSS_URL).is_ok() &&
    env::var(ENVVAR_TTRSS_USERID).is_ok() &&
    env::var(ENVVAR_TTRSS_PASSWORD).is_ok()
}


/// Internal method to validate the environment or force exit
fn validate_or_panic() {
    if ! validate_environment_variables() {
        panic!(r"Validate the environment variables are set. Values retrieved are:
    - {:?}: {:?}
    - {:?}: {:?}
    - {:?}: {:?}
        ", ENVVAR_TTRSS_URL, env::var(ENVVAR_TTRSS_URL), ENVVAR_TTRSS_USERID, env::var(ENVVAR_TTRSS_USERID), ENVVAR_TTRSS_PASSWORD, env::var(ENVVAR_TTRSS_PASSWORD));
    }
}


/// Internal call to populate the session ID
fn populate_session_id() -> String {
    unsafe {
        if SESSION_ID.is_none() {
            let login: ResponseResult = login();
            SESSION_ID = get_session_id_from_login(login);
        }
        match &SESSION_ID {
            Some(x) => {x.to_string()},
            None => "".to_string(),
        }
    }
}

