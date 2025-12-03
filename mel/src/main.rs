// Mimir Encrypted Launcher & supporting libraries
// Copyright (C) 2025  Red Hat, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![warn(clippy::missing_docs_in_private_items, missing_docs)]

//! The Mimir Encrypted Launcher (MEL).  For plaintext Mimir builds, MEL simply launches Solr and
//! Apache.  For encrypted builds, MEL validates the given ACCESS_KEY, decrypts the solr index, and
//! sets up the necessary values for Apache to perform decryption of paywalled content, then
//! launches Solr and Apache.

#[macro_use]
mod debug;
mod error;

use error::MelError;
use mel_libs::access_key::AccessKey;
use mel_libs::crypt::{create_kek, dec, iv, AESParam};
use mel_libs::token_map::{InvalidTokenMap, TokenMap};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;
use std::{env, io};
use std::{fs, process};
use url::Url;

/// The location of the solr index in encrypted builds.
const ENCRYPTED_SOLR_INDEX_PATH: &str = "/opt/solr/server/solr/portal/data.tar.gz.enc";
/// The location of the solr index after decryption, or in plaintext builds.
const DECRYPTED_SOLR_INDEX_PATH: &str = "/opt/solr/server/solr/portal/data.tar.gz";
/// The path to the solr index directory.
const SOLR_PORTAL_PATH: &str = "/opt/solr/server/solr/portal";
/// The path inside the final image to the tokens tsv file.  This file is created by MOE and copied
/// into the image in Containerfile.main.
const TOKENS_TSV_PATH: &str = "/opt/tokens";

/// The string form of the ACCESS_KEY passed in when launching Mimir.
static ACCESS_KEY: OnceLock<Option<String>> = OnceLock::new();

/// Optional custom link URL for Front End app access.
static CUSTOM_LINK: OnceLock<Option<String>> = OnceLock::new();

fn main() {
    debug_println!("MEL: Hello...");

    if let Some(arg1) = env::args().nth(1) {
        if arg1 == "credits" {
            let art = get_credits();
            println!("{art}");
            return;
        }
    }

    // init the ACCESS_KEY
    ACCESS_KEY.get_or_init(|| std::env::var("ACCESS_KEY").ok());

    // init and validate CUSTOM_LINK if present
    CUSTOM_LINK.get_or_init(|| {
        if let Some(url) = std::env::var("CUSTOM_LINK").ok() {
            match validate_url(&url) {
                Ok(validated_url) => Some(validated_url),
                Err(e) => handle_error(e),
            }
        } else {
            None
        }
    });

    // get DEK if needed, and handle errors
    let dek = decrypt_if_needed().unwrap_or_else(|e| {
        // don't error out if encryption is enabled but ACCESS_KEY is missing, instead we want to
        // launch in a limited state.  error & exit for all other error variants.
        if e != MelError::AccessKeyMissing {
            handle_error(e)
        } else {
            None
        }
    });

    // launch solr (in the background) if decryption was successful
    if (is_encrypted() && dek.is_some()) || !is_encrypted() {
        start_solr();
    }

    // launch httpd, with optional dek
    match start_httpd(dek) {
        Ok(_) => {}
        Err(err) => handle_error(err),
    }
}

/// Print a the MelError that occurred.  The error messages in MelError are deliberately terse to
/// avoid hinting at how to get around the encryption barrier, but they contain a numeric error
/// code that can be compared to MelError source code to determine a more detailed reason for
/// failure.
fn handle_error(err: error::MelError) -> ! {
    eprintln!("{err}");
    process::exit(1);
}

/// A newtype to wrap the decrypted Data Encryption Key.
struct Dek(String);

/// If encryption is enabled, attempt to decrypt the user's EDEK to produce the DEK.
fn decrypt_if_needed() -> Result<Option<Dek>, error::MelError> {
    if is_encrypted() {
        debug_println!("MEL: Your Mimir image is encrypted.");
        decrypt_edek().map(Some)
    } else {
        debug_println!("MEL: Your Mimir image is plaintext.");
        Ok(None)
    }
}

/// Was this container image built with encryption enabled?
fn is_encrypted() -> bool {
    option_env!("ENCRYPT").map_or(false, |r| r == "true")
}

/// Attempt to decrypt the EDEK.
fn decrypt_edek() -> Result<Dek, error::MelError> {
    let access_key = ACCESS_KEY
        .get()
        .unwrap(/* safe while ACCESS_KEY is init'd at the beginning of main */)
        .as_ref()
        .ok_or(MelError::AccessKeyMissing)?;

    debug_println!("MEL: Your ACCESS_KEY is {}", &access_key);

    let mak = AccessKey::try_from(access_key.as_str()).map_err(|e| match e {
        mel_libs::access_key::InvalidAccessKey::MissingComponents => {
            error::MelError::AccessKeyInvalidFormat
        }
        mel_libs::access_key::InvalidAccessKey::BadHash => {
            error::MelError::AccessKeyInvalidBindHash
        }
    })?;

    debug_println!("MEL: Your parsed ACCESS_KEY is {:?}", mak);

    debug_println!("MEL: Your hashed token is {:?}", mak.get_token().hash());

    debug_println!("MEL: I will decrypt your EDEK.");

    debug_println!("MEL: MIMIR_SALT {}", mel_libs::crypt::get_salt_hex());

    let tm = TokenMap::load(Path::new(TOKENS_TSV_PATH))
        .map_err(|_| error::MelError::MimirTokenMapUnreadable)?;

    // Check the validity of the TokenMap data.  If it's empty, error and bail out.  If it has only
    // a few records, print a warning and continue.
    if let Err(err) = tm.validate() {
        match err {
            InvalidTokenMap::Meager { .. } => {
                debug_println!("MEL: TokenMap has very few records: {err:?}");
                eprintln!("{}", error::MelError::MimirTokenMapMeager);
            }
            InvalidTokenMap::Empty => {
                return Err(MelError::MimirTokenMapEmpty);
            }
        }
    }

    let edek = tm
        .get(&mak.get_token().hash())
        .cloned()
        .ok_or(error::MelError::TokenMissing)?
        .ok_or(error::MelError::EdekMissing)?;

    debug_println!("MEL: Your EDEK is {}", edek.as_hex());

    let kek = create_kek(&mak.get_token().to_string()).ok_or(error::MelError::KekCreationFailed)?;

    let dek = dec(&kek, edek.data()).map_err(|_| error::MelError::EdekDecryptionFailed)?;

    let dek = AESParam::new(&dek).map_err(|_| error::MelError::DecryptedDekWrongSize)?;

    debug_println!("MEL: Your DEK is {}", dek.as_hex());

    // Decrypt solr data if the encrypted file exists
    if Path::new(ENCRYPTED_SOLR_INDEX_PATH).exists() {
        debug_println!("decrypting solr data");

        decrypt_solr(dek.as_hex(), iv().as_hex())
            .map_err(|_| error::MelError::SolrIndexDecryptionFailed)?;

        debug_println!("solr index decrypted");

        debug_println!("unpacking solr index tar file");

        unpack_solr_tar_gz().map_err(|_e| error::MelError::SolrUnpackFailed)?;

        debug_println!("solr index unpacked");

        clean_up();
    } else if Path::new(SOLR_PORTAL_PATH).exists() {
        debug_println!("using previously unpacked solr index");
    } else {
        return Err(error::MelError::SolrIndexNotFound);
    }

    Ok(Dek(dek.as_hex().to_string()))
}

/// Attempt to decrypt the solr index.
fn decrypt_solr(dek: &str, iv: &str) -> io::Result<()> {
    let status = Command::new("openssl")
        .args([
            "enc",
            "-aes-128-ctr",
            "-d",
            "-in",
            ENCRYPTED_SOLR_INDEX_PATH,
            "-out",
            DECRYPTED_SOLR_INDEX_PATH,
            "-K",
            dek,
            "-iv",
            iv,
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "OpenSSL decryption failed with exit code: {:?}",
                status.code()
            ),
        ))
    }
}

/// Extract the decrypted solr tarball.
fn unpack_solr_tar_gz() -> io::Result<()> {
    let status = Command::new("tar")
        .args(["-xzv", "-f", DECRYPTED_SOLR_INDEX_PATH])
        .current_dir(SOLR_PORTAL_PATH)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Solr tar extraction failed with exit code: {:?}",
                status.code()
            ),
        ))
    }
}

/// clean up the solr encrypted index and the decrypted tarball
fn clean_up() {
    let files_to_remove = [ENCRYPTED_SOLR_INDEX_PATH, DECRYPTED_SOLR_INDEX_PATH];

    for file in files_to_remove {
        if Path::new(file).exists() && fs::remove_file(file).is_err() {
            eprintln!("Failed to remove {}", file);
        }
    }
}

/// Start Apache httpd.  Returns Err if the process spawning fails for any reason.
fn start_httpd(enc_input: Option<Dek>) -> Result<std::process::ExitStatus, error::MelError> {
    // Start HTTPD in the foreground
    let mut httpd_cmd = Command::new("run-httpd");

    let mak_missing =
        ACCESS_KEY.get().unwrap(/* safe while it's init'd at the beginning of main */).is_none();

    // pass var to Apache for use in FE app if present/being used
    if let Some(Some(custom_url)) = CUSTOM_LINK.get() {
        httpd_cmd.env("CUSTOM_LINK", custom_url);
    }

    if let Some(dek) = enc_input {
        // TODO: pass the DEK to MAST via IPC instead of env to Apache
        httpd_cmd
            .env("MIMIR_DEK", dek.0)
            .env("MIMIR_IV", iv().as_hex());
    } else if is_encrypted() && mak_missing {
        httpd_cmd.env("MIMIR_MISSING_ACCESS_KEY", "true");
        missing_mak_slow_warn();
    }

    httpd_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_e| error::MelError::HttpdProcessFailed)?
        .wait()
        .map_err(|_e| error::MelError::HttpdProcessFailed)
}

/// Print a missing MAK warning with remediation instructions, and a slow countdown before
/// continuing.
fn missing_mak_slow_warn() {
    eprintln!("Warning: Missing ACCESS_KEY; Please retrieve an ACCESS_KEY from https://access.redhat.com/offline/access and provide it in the ACCESS_KEY environment variable to enable Search, Solutions, and Articles.");
    eprint!("Launching Red Hat Offline Knowledge Portal (without ACCESS_KEY) in ");

    /// Number of seconds to delay launching Mimir if the image is encrypted and no ACCESS_KEY
    /// was provided.  The delay gives the sysadmin time to read the message and serves as an
    /// additional incentive to register an ACCESS_KEY.
    const MISSING_MAK_LAUNCH_DELAY_SECS: u8 = 10;
    for n in (1..=MISSING_MAK_LAUNCH_DELAY_SECS).rev() {
        eprint!("{n}... ");
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!("launch.");
}

/// Launch solr in the background.  Errors will not be returned but will be printed to stderr.
fn start_solr() {
    // Start solr in the background
    std::thread::spawn(|| {
        match Command::new("run-solr")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(mut child) => {
                if let Err(_e) = child.wait() {
                    eprintln!("{}", MelError::SolrProcessFailed);
                }
            }
            Err(_e) => {
                eprintln!("{}", MelError::SolrProcessFailed);
            }
        }
    });
}

/// credits ascii art
fn get_credits() -> String {
    String::from(
        r#"
                      .                                                  .l
                     ..                                                .':c
                    :l.                                            .,ok0kc
                   ;Oc                                           .ck0Oo,.
                 .c0k.                                          'kXOo;.
                ,x0O;                                          'xX0d,
             .;d0Oo,                                     .''',:xKXOc.
         .,cdkOxdc.                                   .;dOKXXXXXNKx;
      .:x000kdl,.                  .';;;;,,,'...     ,x0O0XXKO0Okxd,
     .lOXXOddc.              .';cox0KXXXXXXXKK0kdl''oO0XNK0K0kkd:;;.
     ;xOKNXkxc             .ckKNWNXKXXNNNXKKXXXX0OkkOOKNX00Oxc;;;'.
     cxk0XXK0xc.         .oKXXNWNXXXXXXK0000OxddxO0O0OOkxddc,,'..
    .:lldkKXK0Oxc.    .:okKKKXWNNXK000kkkkxolcldkOKX0kdoc,'.';.
     ,c;:dkO0XX0Oxc,.'oxodOO0XXXXOxxkkkxxxdoodkOOOkxxxl,..,,:dl'
      .::;;ck00000Okxddodxxkk0KKkxxkOOOOOkdxOOOkddol:,'..';cdOK0l.
        ';;',cok0OO0OOOkkkkxkkOOO0KKK0OOOO00Okoccolc:'...;cdkOKXKx'
          ';;'';clxOOOkOOOkOO00KXXXNX0000Okxxdoc::;,....,,:ldk0KXXd.
            .,,...;oxxxOOOO00KXXNNNX00K000kxkocc:,'....',,:ccldk0X0l.
              .''.':odkOOO0KKKXXXKK0OkOOOOOkdol:;,,''...';clodoodkKk,
                .'.;odxkkkO000KK0000OO0OOOkkxdl:,.......,:lddxxkxdkk:.
                 ';cdddkOO000000KKKK000kxxddxkxl''''...,cldxxkkkkkkOl.  ..
                 :llxxxkOOO0OOkkOK0kxxOOOkxxxkko;,,::,';coxxxxkkxddxdolccc:
               ..:ldOOOkkkO000kkkxkOKKKK00OO0Okdoc:cl:,,;cdxdoclxkxolc;'',.
          :::;coddxkO0KKOxkOxdkkKXKK00OOOOkxdxxxolllcc::cll:;lxo;...';:;.
           .';codooooxO00OdoxdlxkOOxdolcll:,,;::;:oolloocldc;od;.',.,c:'.
             ',,'..';,,;;,;cll;..''....',;:,..''';loloddokklc:. .cd,''.
              ';...':;''..:kOx:.  .',:ccc:,.',,:clddoddooxkl,.  .;c,..
               ..,cclool,,xXNOl:;',;:codxdodxxxddkkxdl:,:xkc:,..;c;..
                .:dlodol:cxK0dldxllolcldxddddxxkOOxo;..,lkx::,.,:,.
                 :kxolcddlxOd:cxkxdk0OxolloxkO0Odl:'...;d0x;;:;;.
                 .:okOOkolk0Ododxdlok000Okkkkxl:'...';;:d0k:;ll:.
                  .,,cdolkOXNOddxdc''ck00ko;,'.....,;;:ok0Oc';:'
                  ;;.;:,;clxkc,'...'cl:ldxxl,'','',;;:ldk0KOl,.
                 ;xc,,,lc........';cxOd:';ooc:do;',,cdxO00000o,.
                .o0x,,oOOd:,'':ox00OOkkoc;',:;cc,;::lxO0KKOkxxl'.
               .:kOkkKNNX0kxlokOKXXXXXXXXKkl;',;:coodxOKXKOOxddc,.
               .ckOKNX0xl;,,'',;:clodk0KKKNXOo:codxkOkk0KK0OOkxo:'
               .ckKKOd:'..,;::ccc:;,,,:dkk0XXX0kxxxkO0O0K0000kxoc,.
         .,:;:clx00kl'.,lc:;;::;;:ldxdc,';ox0XXKK0OOOO0000Oxxkkxc.
          .,ldxxdol;'..';:cldxxl;cooll:'...;codkOOOkxxxddkOxodddl.
             ..:ol:coo;..;lx000Odlc:,',;;:c;,;;::ccc::::ldxxoooo;.
              ,dkxxkOxooxkO0XXXX0kOkkoloodkOdoodoccoodoooddddooo,
             .o0Ok0XK000KXXXNNWNKOKXXX0OkkO00OkO0Oxdkkkkxxkkxoc;.
             ,dkOKXKO0KKXNXNNNWNKK0KNNNXKK0kkKK0KK0kkkxxkkxdol;.
            .:odOKKOO0KKNXKNNNWWXKK0XXXXX00Ok0XKKKX0kxxxxOxc;;.
            .:oxOK0kk0KKX0OXWWWWXKKKXKKKKOxk0KK00KKOxxolodo:'.
            .;ldx00xxO00K0OKWWNNXKK0KKK0OxdOKXK0kOOkxdoll:;;.
            .,codkOxxOOO0KKXNNXXKKKK0OOkkxkKXK00kxxddol:c;'.
             .,ldkOkkOOkO0KXNNXKKXX0OOkkkOKX0kOkdlooo:,,;'
             .,ldkOO000kOOOKKXKKXXXOOOOO0K00kddxxoccl;.''.
              ,cokkk0K0kOOOOO0KXXX0OO0KKKKkxkdoxxdlcc'....
              'codxkOK0xk0KOO0KKK0OkOKK00Oxdkxoxdlc;;.
              ';,:xkxOOkOK0O0KK0kkOOOOOkxxkdxocl:,'...
              .. .cxxkOkkO0OOO0OxkOkxkxocoxolc,....
                 ..:odxxdxOxxkOOxOxodxdlccc:,'.
                  .'';l:cdxodkkxxxool:c:,''..
                   . .'..:l:cdool:cc,.....
                         ...,:;'.....
                           ....
                             .                                                                      
                         ~ Mimir ~     
     
          "Take my knowledge, it will give you aid
           when sundered from the connected world."

# Original 2025 Development Team

## Architects and Lead Engineers

- Jared Sprague (Product Owner)
- Michael Clayton

## Engineers

- Rebekah Cruz
- Jordan White
- Vijay Mhaskar

## QE

- Tushar Sinha

## Product & Program Managers

- Brian Manning
- Christine Bryan
- Melissa Everette
- Brent Baker

## UX Designer

- Fabien Cartal

## Special Thanks

- Mark Shoger
- Bryan Parry

"#,
    )
}

fn validate_url(url: &str) -> Result<String, MelError> {
    match Url::parse(url) {
        Ok(_) => Ok(url.to_string()),
        Err(e) => {
            eprintln!("CUSTOM_LINK validation failed: {}", e);
            Err(MelError::InvalidCustomUrl)
        }
    }
}
