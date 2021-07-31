
extern crate ttrss_api;

fn main() {
    let apilevel: Option<ttrss_api::ApiLevel> = match ttrss_api::get_api_level().expect("Failed to get response").content {
        ttrss_api::Content::GetApiLevel(x) => { Some(x) },
        _ => None,
    };
    println!("API Level: {}", apilevel.unwrap().level);
}
