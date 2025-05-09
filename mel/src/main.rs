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
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWWMMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWNNWNXXXNWMMMMMMMMMMMMMMMMMMMMMMMWNNNNNXKXNXXXXNWWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWWWNNXXXXX0doxKNMMMMMMMMMMMMMMMMMMMWNXKKXNNNNWWNNNNXXNXXNWWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWKOKXXNNNNNNKdccldk0NMMMMMMMMMMMWWNNXXXNWWWWWNXXX00OO00K00O0XNWMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWk:dKXXNNNNNXOocc::coOXWWWWWWNN0kk0XNWWWWWNNKxlodc:;,;:::cloxxxKNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMM0;,d0XNWWWNX0Oo;,,cdOXWWWWNXOkxkOKNWWWNXklc;'.','.'''',,'..';:lxXMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWO;.:kKXNNNNX0Okkk0XWMMMMWX0xxO000KXXX0xl;'........''',,'...'''',dKWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMK:.'lkkkOKKKKKNWWWMMMMMWNKK0kOKXXK0O0xc:;,'.......''.....'',''',;ckKWMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWO;..':lokOOKNWWWMMMMMWWWNXXKOxO0000Od:;,,'................''',;;:lloKMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWk,....,cokO0NWWWWWWMWWWNNXXXK0kkkkdl:,'''.....';,;::,.......';:::;';OMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMKc.....:ok0KNWWWWWWNNWWNNNNXKOdlloo:,,'......:kKKXNNXOc'...',;;,,'',oKWMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMM0;....,oOKXXNNXXWWNWWWNNNX000kdddlc:;,'.....;dOKNWWWMNx;...''',,,;;;lKMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMXl...,okKNNNNNXNNNNNNNWWNNX0kdodoc:;;,'.....':dk0NWWWWWO;..',;:clc;;dNMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWk,.,d0KKXXNXKKK00KXXKOO0KX0kollcclolc:''',',;;lkXNWWWWWO;',:clodc::kWMMMMMMMMMM
NNWMMMMMMMMMMMMMMMMMWk,.;ooldxdxkkxdodxdo:,;lxkxdolloooccdo:;;,''';cx00XWWWMXl';lxxxoc::kWMMMMMMMMMM
lx00XWMMMMMMMMMMMMMMWk;..''..'''oOxl,.........',:llloollooloxocc:''lOK00XNNWNd;cdOOxolcckWMMMMMMMMMM
ddkKKXNMMMMMMMMMMMMMWO;........:0WXkc,...,::,'';oxdxxddoodddl:;,...:kKKKKNWWXdcdO0kdolccOWMMMMMMMMMM
W0OXXKKXMMMMMMMMMMMWXo'..,ll:::kNNK0Oxddooooodk0XK0Odoodolc,.:l:,..:xdoOXNNNKxok0K0xollOWMMMMMMMMMMM
WK0XXXKXWMMMMMMMMMMNOc,'.;okxdo0NNK00O0KK0OkkO00Odoc,,,;:,',;::,...;xxoOXNNX0xk0KK0OxloKMMMMWNXXXXXX
MXO0XXK0NMMMMMMMMWNx:;,...';cokXWN0kxdxKXK0kxl:;,....';,;::::;.....;cdk0KNWNkok0KKKOdcdXMWNXXXKKOxoo
MW0k00xoxNWMMMMWNKxoc;'......:dO0klcc::dOKkl;,'.....,;cc;;;;'.....',:k0xxXWKook0XX0kdlOWMN00XKkl:lx0
MW0oddlccok0KKOkxdooc,'.'::'.,:;,...;cxkdxxo:;,;;,',cl::;;;;,.''''',:xKK0KNOllx0XKOkoo0WNK0Od:,:kNWW
MMNxcc:::cclclllccc:;'';dd,.:dkc..'o0KXX0xoollolcclclxdldxddo:''',',:co0NNX0ocdk0KKOocx000kl,'cKWMMM
MMM0l;,;;:c::::c:;;;,,;x0l;lO0xl;,cx0XNWWX0xllxkOkxkkOxol:'.,,'...',;;:oONN0l:lodO00xllk0k:..:0WMMMM
MMMWX0kdc;;;::::;;;:dkOOxox00d;''',:cldOKNNNXkocoxxxOK0kol:'.';;,,,,,,:dkOKK0occcodooodol:..'oNMMMMM
MMMMMMMWKxllc::codxOXKkdlcxOd;.':odlc;',cx0NWXklcclllok00xoc;,,,,;;;;;cxxdx0NXo::::cccc:,...;OWMMMMM
MMMMMMMMMWWNXK0KNWNKOdlccodl;.,lkKK0kdc,',ckXXOxxdddolc:colc;''..',;:::dkkk0XXkc;;;;:;'....'dNMWMMMM
MMMWNNNWMMWWMMMWWNK0Kklllc:,,;oOXNWN0kdl:'.:O0dloddxO0Okoc:cl;''....,;;cdkk0XXXKx;,,,'...,lkXWMMMMMM
MMMNXNWWMNKKXXNWWXKXWOc;;;;cokKNWWWWN0kxo:;cdc;coooodxkOKOc,;c,..'','''';lkKXXNWNOl;,;,,cOWMMMMMMMMM
MMMNXWMWKkOKXKOXWWX0kl,',lxO0KXNWWWWWXXXKxllo:clldxdllxO00d,.;;...'',,''',ckXNXNWWWXKXXXNWMMMMMMMMMM
MMMWXXX0kKWMWOxOKOdc;;::oOKK0KXNNNWWWNXNNXkolol:,,:odccdO00xcclc;,'..',;cccdkkdoxXWMMMMMMMMMMMMMMMMM
MMMMWWNKKXWMWXOxoooc:clloxOKXXXXXXNWWNKKK0Oddkkl;,;lxol:;:cxOkdollc:;:lxxdoldO0xldXMMWWWMMMMMMMMMMMM
MMMMMMMNKXNWNXKOO0koc:ccld0KKXXXNNKOk0KOkxxOKOl:::;:c:cc;;,;loc;,:cc:cc:;;looOXXOdOKXK00KWMMMMMMMMMM
MMMMMMMWWWWNNXXNNKkxo;codOKKXNNNKd:;l0Kkod0NNkoc,,,;cdo::;;,',,,;;;;'...'.,oOKK0XXKKXNNXOkXMMMMMMMMM
MMMMMMMMMMWNNWWWXxoc:lol:o0XXXNNOl:oOklcod0NNK00xc;;;oo;,,,,'..',;llc;';cc::xKKKNWNXWMWN0KNMWMMMMMMM
MMMMMMMMMMWWNXK0xlccc;,'':OK0OKNKxlxd;',lxxkKKKXXOxocc:;;::;'.....':cc;;:oddk00KXNXKNWWKkKNNNWMMMMMM
MMMMMWWWWMWKO00Okdllc,,:okO00xdKNKkdollccloolloxkOOOxdddxkkxc,..',,,,:lllccdkO000KNWWMMWNXNWMMMMMMMM
MMMMMWWNNWNOOKKOdc;;:;ck0OkdkkdxKNXOddxkxodoc:;:clllcll:;;cod:,,;:::;;oO0kdooodxkOO0XWMMMMMMMMMMMMMM
MMMMMMMMWWWNKK0dlldxc,;oxOkl;locxKXKkodxxooxxl:;,''''';ldc'':;;clllodloOKKXXXK00XX0xxKWWWWMMMMMMMMMM
MMMMMMMMMMMMWXOxkOko:;;:dkd::odlld0XOlcdOOdlodl:;,''...,dk:';:cxkkkO0kkKNKXWWWMMMMWKxONWNXXWMMMMMMMM
MMMMMMMMMMWXK00XXOkdcclodoloddoolo0X0c:xOkl;:oo::cc;,'.'::,;:lk0Odld0KXWWNXNNWMMMMMW0d0NNNNWMMMMMMMM
MMMMMMMWNX00KXWNK00kooodolllc:cdxkKOlcdxol:,;ldolc:;,,,;;;;clkXKkco0NWWMWWWWWWWNNNWXkkXWWMMMMMMMMMMM
MMMMMWX0000KNWWNKOxddlllcccccldO00kxk0klc:;;:cdxc,,,;,';;:coOXNNKxxOXWWMMMWWWMWNNNNKKNWMMMMMMMMMMMMM
MMMMWKk0WMWMMMMWNklddlcclodxkOKK0Oxxxxo::;;cdxko;;ccol;,:odOXNNWWWNXXKKNMMMWWMWWWWMMMMMMMMMMMMMMMMMM
MMMMWXO0NWNNWMMMNOdkkdllxO0000Oxlc;;clc:,;okkdl:cxOO0kl,:kNWWWWWMMMMWNOOWMMMWMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMWXXXNNWNNKOkkkxxxk00OKXKxlccoxkkkdoxkdc:loOKKKKOlckKXXNWWWMMMMMN0KWWWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMWWMWNKK0kOkkKXK00O0XX0xdxk0KXXKOOkxddxOXNXKKXKxdOXNNNWWMMMMMMWXXNNWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMWNXNWXOkOKNNNXKKXXK0O0O0XNNK0kkkO0KXWWNXXNWWNXXXXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMWNNNWWXOOKNWWNXXXXNX0O0XNNKOkO00KXNNWMWNXNNWWNNWWNNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMWXNWWXKO0NWWWNNXXXNXO0XWNNKOk0XNWNNWWWWWNNNWWNNNNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"When you find yourself sundered from the connected world, may the knowledge contained herein give you aid." - Jared Sprague

# Original 2025 Development Team

## Architects and Lead Engineers

- Jared Sprague (Product Owner)
- Michael Clayton

## Engineers

- Rebekah Cruz
- Jordan White
- Vijay Mhaskar

## Product & Program Managers

- Brian Manning
- Christine Bryan
- Melissa Everette

"#,
    )
}
