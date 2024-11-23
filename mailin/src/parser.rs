use nom::branch::alt;
use nom::multi::many0;
use nom::bytes::complete::{is_not, tag, tag_no_case, take_while1};
use nom::character::{is_alphanumeric, complete::space0};
use nom::combinator::{map, map_res, value, opt};
use nom::sequence::{pair, preceded, terminated, delimited};
use nom::IResult;

use crate::response::*;
use crate::smtp::{Cmd, Credentials};
use std::str;

//----- Parser -----------------------------------------------------------------

// Parse a line from the client
pub fn parse(line: &[u8]) -> Result<Cmd, Response> {
    command(line).map(|r| r.1).map_err(|e| match e {
        nom::Err::Incomplete(_) => MISSING_PARAMETER,
        nom::Err::Error(_) => SYNTAX_ERROR,
        nom::Err::Failure(_) => SYNTAX_ERROR,
    })
}

// Parse an authentication response from the client
pub fn parse_auth_response(line: &[u8]) -> Result<&[u8], Response> {
    auth_response(line).map(|r| r.1).map_err(|_| SYNTAX_ERROR)
}

fn command(buf: &[u8]) -> IResult<&[u8], Cmd> {
    terminated(
        alt((
            helo, ehlo, mail, rcpt, data, rset, quit, vrfy, noop, starttls, auth,
        )),
        tag(b"\r\n"),
    )(buf)
}

fn hello_domain(buf: &[u8]) -> IResult<&[u8], &str> {
    map_res(is_not(b" \t\r\n" as &[u8]), str::from_utf8)(buf)
}

fn helo(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parse_domain = preceded(cmd(b"helo"), hello_domain);
    map(parse_domain, |domain| Cmd::Helo { domain })(buf)
}

fn ehlo(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parse_domain = preceded(cmd(b"ehlo"), hello_domain);
    map(parse_domain, |domain| Cmd::Ehlo { domain })(buf)
}

fn mail_path(buf: &[u8]) -> IResult<&[u8], &str> {
    map_res(is_not(b" <>\t\r\n" as &[u8]), str::from_utf8)(buf)
}

fn take_all(buf: &[u8]) -> IResult<&[u8], &str> {
    map_res(is_not(b"\r\n" as &[u8]), str::from_utf8)(buf)
}

fn body_eq_8bit(buf: &[u8]) -> IResult<&[u8], bool> {
    // Allow optional spaces before `BODY=`
    let preamble = pair(space0, tag_no_case(b"body="));

    // Match either `8BITMIME` or `7BIT`
    let is8bit = alt((
        value(true, tag_no_case(b"8bitmime")),
        value(false, tag_no_case(b"7bit")),
    ));

    // Combine preamble with `is8bit` using `preceded`
    preceded(preamble, is8bit)(buf)
}

fn is8bitmime(buf: &[u8]) -> IResult<&[u8], bool> {
    if let Ok((remaining, result)) = body_eq_8bit(buf) {
        Ok((remaining, result))
    } else {
        Ok((buf, false)) // No match, but don't consume
    }
}

fn mail(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let preamble = preceded(
        tag_no_case("mail from:"), // Match "MAIL FROM:" case-insensitively
        many0(tag(" ")),           // Skip any spaces after "MAIL FROM:"
    );

    let email_parser = delimited(
        tag("<"),
        mail_path,
        tag(">"),
    );

    let is8bitmime_parser = preceded(
        many0(tag(" ")), // Allow optional spaces before BODY=
        is8bitmime,
    );

    let parser = pair(
        preceded(preamble, email_parser),
        opt(is8bitmime_parser), // Optional BODY= clause
    );

    map(parser, |(email, is8bit)| Cmd::Mail {
        reverse_path: email,
        is8bit: is8bit.unwrap_or(false),
    })(buf)
}

fn rcpt(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let preamble = preceded(
        tag_no_case("rcpt to:"),
        many0(tag(" ")),
    );

    let email_parser = delimited(
        tag("<"),
        mail_path,
        tag(">"),
    );

    let parser = preceded(preamble, email_parser);

    map(parser, |email_bytes| {
        let path = email_bytes;
        Cmd::Rcpt { forward_path: path }
    })(buf)
}

fn data(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Data, tag_no_case(b"data"))(buf)
}

fn rset(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Rset, tag_no_case(b"rset"))(buf)
}

fn quit(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Quit, tag_no_case(b"quit"))(buf)
}

fn vrfy(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let preamble = preceded(cmd(b"vrfy"), take_all);
    value(Cmd::Vrfy, preamble)(buf)
}

fn noop(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Noop, tag_no_case(b"noop"))(buf)
}

fn starttls(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::StartTls, tag_no_case(b"starttls"))(buf)
}

fn is_base64(chr: u8) -> bool {
    is_alphanumeric(chr) || (chr == b'+') || (chr == b'/' || chr == b'=')
}

fn auth_initial(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(space, take_while1(is_base64))(buf)
}

fn auth_response(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    terminated(take_while1(is_base64), tag("\r\n"))(buf)
}

fn empty(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    Ok((buf, b"" as &[u8]))
}

fn auth_plain(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parser = preceded(tag_no_case(b"plain"), alt((auth_initial, empty)));
    map(parser, sasl_plain_cmd)(buf)
}

fn auth_login(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parser = preceded(tag_no_case(b"login"), alt((auth_initial, empty)));
    map(parser, sasl_login_cmd)(buf)
}

fn auth(buf: &[u8]) -> IResult<&[u8], Cmd> {
    preceded(cmd(b"auth"), alt((auth_plain, auth_login)))(buf)
}

//---- Helper functions ---------------------------------------------------------

// Return a parser to match the given command
fn cmd(cmd_tag: &[u8]) -> impl Fn(&[u8]) -> IResult<&[u8], (&[u8], &[u8])> + '_ {
    move |buf: &[u8]| pair(tag_no_case(cmd_tag), space)(buf)
}

// Match one or more spaces
fn space(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|b| b == b' ')(buf)
}

fn sasl_plain_cmd(param: &[u8]) -> Cmd {
    if param.is_empty() {
        Cmd::AuthPlainEmpty
    } else {
        let creds = decode_sasl_plain(param);
        Cmd::AuthPlain {
            authorization_id: creds.authorization_id,
            authentication_id: creds.authentication_id,
            password: creds.password,
        }
    }
}

fn sasl_login_cmd(param: &[u8]) -> Cmd {
    if param.is_empty() {
        Cmd::AuthLoginEmpty
    } else {
        Cmd::AuthLogin {
            username: decode_sasl_login(param),
        }
    }
}

// Decodes the base64 encoded plain authentication parameter
pub(crate) fn decode_sasl_plain(param: &[u8]) -> Credentials {
    let decoded = base64::decode(param);
    if let Ok(bytes) = decoded {
        let mut fields = bytes.split(|b| b == &0u8);
        let authorization_id = next_string(&mut fields);
        let authentication_id = next_string(&mut fields);
        let password = next_string(&mut fields);
        Credentials {
            authorization_id,
            authentication_id,
            password,
        }
    } else {
        Credentials {
            authorization_id: String::default(),
            authentication_id: String::default(),
            password: String::default(),
        }
    }
}

// Decodes base64 encoded login authentication parameters (in login auth, username and password are
// sent in separate lines)
pub(crate) fn decode_sasl_login(param: &[u8]) -> String {
    let decoded = base64::decode(param).unwrap_or_default();
    String::from_utf8(decoded).unwrap_or_default()
}

fn next_string(it: &mut dyn Iterator<Item = &[u8]>) -> String {
    it.next()
        .map(|s| str::from_utf8(s).unwrap_or_default())
        .unwrap_or_default()
        .to_owned()
}

//---- Tests --------------------------------------------------------------------

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn auth_initial_plain() {
        let res = parse(b"auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n");
        match res {
            Ok(Cmd::AuthPlain {
                authorization_id,
                authentication_id,
                password,
            }) => {
                assert_eq!(authorization_id, "test");
                assert_eq!(authentication_id, "test");
                assert_eq!(password, "1234");
            }
            _ => panic!("Auth plain with initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_initial_login() {
        let res = parse(b"auth login ZHVtbXk=\r\n");
        match res {
            Ok(Cmd::AuthLogin { username }) => {
                assert_eq!(username, "dummy");
            }
            _ => panic!("Auth login with initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_empty_plain() {
        let res = parse(b"auth plain\r\n");
        match res {
            Ok(Cmd::AuthPlainEmpty) => {}
            _ => panic!("Auth plain without initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_empty_login() {
        let res = parse(b"auth login\r\n");
        match res {
            Ok(Cmd::AuthLoginEmpty) => {}
            _ => panic!("Auth login without initial response incorrectly parsed"),
        };
    }
}
