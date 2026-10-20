//! Invented export files, one per format `import::detect` knows, with what it reads from them.
//! No real site, name or password: `example.*` hosts, `alex`, `test-password-*`, and the
//! well-known test key `JBSWY3DPEHPK3PXP`.

use crate::ImportFormat as F;

/// One sample: its name, its bytes and the expected summary
/// `(format, found, logins, codes, skipped, encrypted, archive)`.
pub struct Sample {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub expect: (F, u32, u32, u32, u32, bool, bool),
}

/// A Chrome export with two logins and a row without a password: the sample `nodkey import` and
/// the fake phone tests send.
pub const CHROME_CSV: &[u8] = b"name,url,username,password,note\n\
example.com,https://example.com/login,alex@example.com,test-password-1,\n\
shop.example.net,https://shop.example.net/,alex,test-password-2,\"a note, with a comma\"\n\
notes.example.org,https://notes.example.org/,alex,,\n";

pub const SAMPLES: &[Sample] = &[
    Sample {
        name: "chrome_csv",
        bytes: CHROME_CSV,
        expect: (F::ChromeCsv, 2, 2, 0, 1, false, false),
    },
    Sample {
        name: "chrome_csv_bom_crlf",
        bytes: b"\xef\xbb\xbfname,url,username,password\r\nexample.com,https://example.com/,alex,test-password-1\r\n\r\n",
        expect: (F::ChromeCsv, 1, 1, 0, 0, false, false),
    },
    Sample {
        name: "firefox_csv",
        bytes: br#""url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://example.com","alex@example.com","test-password-1",,"https://example.com","{00000000-0000-0000-0000-000000000001}","1700000000000","1700000000000","1700000000000"
"https://mail.example.org","alex","test ""quoted"" password",,"https://mail.example.org","{00000000-0000-0000-0000-000000000002}","1700000000000","1700000000000","1700000000000"
"#,
        expect: (F::FirefoxCsv, 2, 2, 0, 0, false, false),
    },
    Sample {
        name: "apple_passwords_csv",
        bytes: b"Title,URL,Username,Password,Notes,OTPAuth\n\
example.com (alex@example.com),https://example.com/,alex@example.com,test-password-1,,otpauth://totp/Example:alex@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example\n\
example.net (alex),https://example.net/,alex,test-password-2,\"line one\nline two\",\n",
        expect: (F::ApplePasswordsCsv, 2, 2, 1, 0, false, false),
    },
    Sample {
        name: "bitwarden_csv",
        bytes: b"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
,,login,Example,,,0,https://example.com,alex@example.com,test-password-1,JBSWY3DPEHPK3PXP\n\
,,note,A note,just a note,,0,,,,\n",
        expect: (F::BitwardenCsv, 1, 1, 1, 1, false, false),
    },
    Sample {
        name: "bitwarden_json",
        bytes: br#"{"encrypted":false,"folders":[],"items":[
 {"id":"1","type":1,"name":"Example","login":{"username":"alex@example.com","password":"test-password-1","totp":"otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP","uris":[{"uri":"https://example.com"}]}},
 {"id":"2","type":1,"name":"Example Net","login":{"username":"alex","password":"test-password-2","totp":null}},
 {"id":"3","type":2,"name":"A secure note","secureNote":{"type":0},"notes":"just a note"}]}
"#,
        expect: (F::BitwardenJson, 2, 2, 1, 1, false, false),
    },
    Sample {
        name: "bitwarden_json_encrypted",
        bytes: br#"{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA","kdfType":0,"kdfIterations":600000,"encKeyValidation_DO_NOT_EDIT":"2.AAAA","data":"2.BBBB"}"#,
        expect: (F::BitwardenJson, 0, 0, 0, 0, true, false),
    },
    Sample {
        name: "1password_csv",
        bytes: b"Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
Example,https://example.com,alex@example.com,test-password-1,,false,false,,\n",
        expect: (F::OnePasswordCsv, 1, 1, 0, 0, false, false),
    },
    Sample {
        name: "lastpass_csv",
        bytes: b"url,username,password,totp,extra,name,grouping,fav\n\
https://example.com,alex@example.com,test-password-1,,,Example,,0\n\
http://sn,,,,NoteType:Server,A secure note,,0\n",
        expect: (F::LastPassCsv, 1, 1, 0, 1, false, false),
    },
    Sample {
        name: "dashlane_csv",
        bytes: b"username,username2,username3,title,password,note,url,category,otpSecret\n\
alex@example.com,,,Example,test-password-1,,https://example.com,,\n",
        expect: (F::DashlaneCsv, 1, 1, 0, 0, false, false),
    },
    Sample {
        name: "proton_pass_csv",
        bytes: b"name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
Example,https://example.com,alex@example.com,,test-password-1,,,1700000000,1700000000,Personal\n",
        expect: (F::ProtonPassCsv, 1, 1, 0, 0, false, false),
    },
    Sample {
        name: "nordpass_csv",
        bytes: b"name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,expirydate,type\n\
Example,https://example.com,,alex@example.com,test-password-1,,,,,,password\n\
Test card,,,,,,Alex Example,4242424242424242,123,12/30,credit_card\n",
        expect: (F::NordPassCsv, 1, 1, 0, 1, false, false),
    },
    Sample {
        name: "keepassxc_csv",
        bytes: br#""Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","Example","alex@example.com","test-password-1","https://example.com","","otpauth://totp/Example:alex?secret=JBSWY3DPEHPK3PXP&issuer=Example","0","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z"
"#,
        expect: (F::KeePassXcCsv, 1, 1, 1, 0, false, false),
    },
    Sample {
        name: "generic_csv",
        bytes: b"site,login,password\nexample.com,alex,test-password-1\n",
        expect: (F::GenericCsv, 1, 1, 0, 0, false, false),
    },
    Sample {
        name: "otpauth_list",
        bytes: b"otpauth://totp/Example:alex@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example\n\
otpauth://totp/Example%20Net:alex?secret=KRSXG5CTMVRXEZLU&issuer=Example%20Net\n\
\n\
not a link\n",
        expect: (F::OtpauthList, 2, 0, 2, 1, false, false),
    },
    Sample {
        name: "2fas_json",
        bytes: br#"{"services":[{"name":"Example","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"alex@example.com","issuer":"Example","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP"},"order":{"position":0}}],"groups":[],"updatedAt":1700000000000,"schemaVersion":4,"appVersionCode":5000000,"appOrigin":"ios"}"#,
        expect: (F::TwoFasJson, 1, 0, 1, 0, false, false),
    },
    Sample {
        name: "2fas_json_encrypted",
        bytes: br#"{"services":[],"groups":[],"updatedAt":1700000000000,"schemaVersion":4,"servicesEncrypted":"AAAA:BBBB:CCCC","reference":"DDDD"}"#,
        expect: (F::TwoFasJson, 0, 0, 0, 0, true, false),
    },
    Sample {
        name: "aegis_json",
        bytes: br#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[{"type":"totp","uuid":"00000000-0000-0000-0000-000000000001","name":"alex@example.com","issuer":"Example","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}}"#,
        expect: (F::AegisJson, 1, 0, 1, 0, false, false),
    },
    Sample {
        name: "aegis_json_encrypted",
        bytes: br#"{"version":1,"header":{"slots":[{"type":1}],"params":{"nonce":"00","tag":"00"}},"db":"AAAA"}"#,
        expect: (F::AegisJson, 0, 0, 0, 0, true, false),
    },
    Sample {
        name: "zip_archive",
        bytes: b"PK\x03\x04\x14\x00\x00\x00\x08\x00credentials.csv",
        expect: (F::Unknown, 0, 0, 0, 0, false, true),
    },
    Sample {
        name: "csv_without_password",
        bytes: b"name,url\nExample,https://example.com\n",
        expect: (F::Unknown, 0, 0, 0, 0, false, false),
    },
    Sample {
        name: "plain_text",
        bytes: b"hello\n",
        expect: (F::Unknown, 0, 0, 0, 0, false, false),
    },
];
