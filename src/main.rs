use std::borrow::Cow;
use std::env;
use std::rc::Rc;
use tokio_core::reactor::Handle;

use futures::{Future, Stream};
use telegram_bot::*;
use tokio_core::reactor::Core;

use lazy_static::lazy_static;
use regex::Regex;

fn extract_email<'a, T: Into<&'a str>>(text: T) -> Result<&'a str, &'static str> {
    lazy_static! {
        // from https://emailregex.com/
        static ref RE: Regex = Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).unwrap();
    }
    let re_match = RE
        .find(&text.into())
        .ok_or("Input contains no valid email address")?;
    Ok(re_match.as_str())
}

fn get_num_of_breaches<'a>(email: impl Into<&'a str>) -> reqwest::Result<usize> {
    let request_url = format!(
        "https://haveibeenpwned.com/api/v2/breachedaccount/{}?truncateResponse=true",
        email.into()
    );
    let mut response = reqwest::get(&request_url)?;
    // no need to parse json...
    let count = response.text()?.matches('{').count();
    Ok(count)
}

fn run_pwned(
    api: Api,
    message: Rc<Message>,
    handle: &Handle,
) -> Result<(), Box<std::error::Error>> {
    let email = if let MessageKind::Text { ref data, .. } = message.kind {
        extract_email(data.as_str())?
    } else {
        unreachable!();
    };
    let num_breaches = get_num_of_breaches(email)?;
    let mut reply = message.text_reply(
        format!(
            "The email {} has been breached {} times!\nVisit https://haveibeenpwned.com for more information.",
            email,
            num_breaches));
    reply.disable_preview();
    api.spawn(reply);

    Ok(())
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = &core.handle();

    let token = env::var("TELEGRAM_BOT_TOKEN").unwrap();
    let api = Api::configure(token).build(core.handle()).unwrap();

    // Fetch new updates via long poll method
    let future = api.stream().for_each(|update| {
        if let UpdateKind::Message(message) = update.kind {
            if let MessageKind::Text { ref data, .. } = message.kind {
                if data.starts_with("/pwned") {
                    let message = Rc::new(message);
                    let result = run_pwned(api.clone(), message.clone(), &handle);
                    if let Err(err) = result {
                        api.spawn(message.text_reply(format!("{}", err)))
                    }
                }
            }
        }

        Ok(())
    });

    core.run(future).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn can_parse_valid_email_from_command() {
        assert_eq!(
            "example@test.com",
            extract_email(r"\pwned? example@test.com").expect("Failed to extract valid email")
        );
    }
}
