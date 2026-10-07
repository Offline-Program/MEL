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

mod debug;
#[cfg(feature = "mcp")]
mod mcp;

use debug::debug_println;

use mel_libs::access_key::AccessKey;
use mel_libs::crypt::{create_kek, dec, iv, AESParam};
use mel_libs::error::MelError;
use mel_libs::infer::init_inference;
use mel_libs::token_map::{InvalidTokenMap, TokenMap};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{env, io};
use std::{fs, process};

/// The location of the encrypted solr index — the subscription-only `portal-protected` collection
/// (the public `portal` collection ships unencrypted).
const ENCRYPTED_SOLR_INDEX_PATH: &str =
    "/opt/solr/server/solr/portal-protected/data.tar.gz.enc";
/// The location of the solr index after decryption.
const DECRYPTED_SOLR_INDEX_PATH: &str = "/opt/solr/server/solr/portal-protected/data.tar.gz";
/// The path to the protected solr collection directory.
const SOLR_PROTECTED_PATH: &str = "/opt/solr/server/solr/portal-protected";
/// Comma-separated shard list pointing Solr's distributed `/select` handler at both the public
/// `portal` collection and the subscription-only `portal-protected` collection, so that search
/// federates across public and protected content transparently.  Exported to the environment for
/// `run-solr`, which forwards it as the `mimir.search.shards` JVM system property.
const MIMIR_SEARCH_SHARDS: &str =
    "localhost:8983/solr/portal,localhost:8983/solr/portal-protected";
/// The path inside the final image to the tokens tsv file.  This file is created by MOE and copied
/// into the image in Containerfile.main.
const TOKENS_TSV_PATH: &str = "/opt/tokens";

/// The `host:port` Solr listens on inside the container.
const SOLR_ADDR: &str = "127.0.0.1:8983";
/// The maximum time to wait for all queried Solr cores to answer their ping handler before
/// starting httpd anyway.  Bounded so a Solr failure can't hang the container forever.
const SOLR_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait between Solr readiness poll attempts.
const SOLR_READINESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Per-probe socket timeout for a single Solr readiness request.
const SOLR_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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

    // initialize inference, if enabled
    match init_inference() {
        Ok(_) => {}
        Err(err) => handle_error(err),
    }

    // The portal-protected collection is searchable when it has a usable index: either a DEK was
    // produced (encrypted build + valid ACCESS_KEY, so it was just decrypted) or the build is
    // plaintext (it ships unencrypted and is always present).  When available, enable distributed
    // search across both collections.
    let protected_available = dek.is_some() || !is_encrypted();

    // launch solr (in the background)
    start_solr(protected_available);

    // Wait for Solr's cores to finish loading before starting httpd.  Solr's HTTP listener comes
    // up well before its cores register, so without this gate the first user search races core
    // startup and Apache proxies back Solr's "SolrCore is loading" HTTP 503.
    wait_for_solr_ready(protected_available);

    // launch MCP server.
    #[cfg(feature = "mcp")]
    let mcp_shutdown_handle = mcp::start();

    // launch httpd, with optional dek - blocks until httpd exits
    let httpd_result = start_httpd(dek);

    // httpd has exited - cancel the MCP server
    #[cfg(feature = "mcp")]
    mcp_shutdown_handle.cancel();
    match httpd_result {
        Ok(_) => {}
        Err(err) => handle_error(err),
    }
}

/// Print a the MelError that occurred.  The error messages in MelError are deliberately terse to
/// avoid hinting at how to get around the encryption barrier, but they contain a numeric error
/// code that can be compared to MelError source code to determine a more detailed reason for
/// failure.
fn handle_error(err: MelError) -> ! {
    eprintln!("{err}");
    process::exit(1);
}

/// A newtype to wrap the decrypted Data Encryption Key.
struct Dek(String);

/// If encryption is enabled, attempt to decrypt the user's EDEK to produce the DEK.
fn decrypt_if_needed() -> Result<Option<Dek>, MelError> {
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
fn decrypt_edek() -> Result<Dek, MelError> {
    let access_key = ACCESS_KEY
        .get()
        .unwrap(/* safe while ACCESS_KEY is init'd at the beginning of main */)
        .as_ref()
        .ok_or(MelError::AccessKeyMissing)?;

    debug_println!("MEL: Your ACCESS_KEY is {}", &access_key);

    let mak = AccessKey::try_from(access_key.as_str()).map_err(|e| match e {
        mel_libs::access_key::InvalidAccessKey::MissingComponents => {
            MelError::AccessKeyInvalidFormat
        }
        mel_libs::access_key::InvalidAccessKey::BadHash => MelError::AccessKeyInvalidBindHash,
    })?;

    debug_println!("MEL: Your parsed ACCESS_KEY is {:?}", mak);

    debug_println!("MEL: Your hashed token is {:?}", mak.get_token().hash());

    debug_println!("MEL: I will decrypt your EDEK.");

    debug_println!("MEL: MIMIR_SALT {}", mel_libs::crypt::get_salt_hex());

    let tm = TokenMap::load(Path::new(TOKENS_TSV_PATH))
        .map_err(|_| MelError::MimirTokenMapUnreadable)?;

    // Check the validity of the TokenMap data.  If it's empty, error and bail out.  If it has only
    // a few records, print a warning and continue.
    if let Err(err) = tm.validate() {
        match err {
            InvalidTokenMap::Meager { .. } => {
                debug_println!("MEL: TokenMap has very few records: {err:?}");
                eprintln!("{}", MelError::MimirTokenMapMeager);
            }
            InvalidTokenMap::Empty => {
                return Err(MelError::MimirTokenMapEmpty);
            }
        }
    }

    let edek = tm
        .get(&mak.get_token().hash())
        .cloned()
        .ok_or(MelError::TokenMissing)?
        .ok_or(MelError::EdekMissing)?;

    debug_println!("MEL: Your EDEK is {}", edek.as_hex());

    let kek = create_kek(&mak.get_token().to_string()).ok_or(MelError::KekCreationFailed)?;

    let dek = dec(&kek, edek.data()).map_err(|_| MelError::EdekDecryptionFailed)?;

    let dek = AESParam::new(&dek).map_err(|_| MelError::DecryptedDekWrongSize)?;

    debug_println!("MEL: Your DEK is {}", dek.as_hex());

    // The portal collection ships UNENCRYPTED (public content: CVEs, errata, docs) so it is
    // searchable without an ACCESS_KEY.  Only the protected (subscription-only) collection is
    // encrypted — it holds Red Hat Knowledge Base content (Solutions & Articles) and is decrypted
    // here with the DEK derived from the ACCESS_KEY.  Distributed search across both collections is
    // enabled later in start_solr, gated on whether a DEK was produced.
    if Path::new(ENCRYPTED_SOLR_INDEX_PATH).exists() {
        debug_println!("decrypting protected solr data");

        decrypt_solr(dek.as_hex(), iv().as_hex())
            .map_err(|_| MelError::SolrIndexDecryptionFailed)?;

        debug_println!("protected solr index decrypted");

        debug_println!("unpacking protected solr index tar file");

        unpack_solr_tar_gz().map_err(|_e| MelError::SolrUnpackFailed)?;

        debug_println!("protected solr index unpacked");

        clean_up();
    } else if Path::new(SOLR_PROTECTED_PATH).exists() {
        debug_println!("using previously unpacked solr index");
    } else {
        return Err(MelError::SolrIndexNotFound);
    }

    Ok(Dek(dek.as_hex().to_string()))
}

/// Attempt to decrypt the protected solr index.
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
        Err(io::Error::other(format!(
            "OpenSSL decryption failed with exit code: {:?}",
            status.code()
        )))
    }
}

/// Extract the decrypted protected solr tarball into the protected collection directory.
fn unpack_solr_tar_gz() -> io::Result<()> {
    let status = Command::new("tar")
        .args(["-xzv", "-f", DECRYPTED_SOLR_INDEX_PATH])
        .current_dir(SOLR_PROTECTED_PATH)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Solr tar extraction failed with exit code: {:?}",
            status.code()
        )))
    }
}

/// clean up the protected solr encrypted index and decrypted tarball.
fn clean_up() {
    let files_to_remove = [ENCRYPTED_SOLR_INDEX_PATH, DECRYPTED_SOLR_INDEX_PATH];

    for file in files_to_remove {
        if Path::new(file).exists() && fs::remove_file(file).is_err() {
            eprintln!("Failed to remove {file}");
        }
    }
}

/// Start Apache httpd.  Returns Err if the process spawning fails for any reason.
fn start_httpd(enc_input: Option<Dek>) -> Result<std::process::ExitStatus, MelError> {
    // Start HTTPD in the foreground
    let mut httpd_cmd = Command::new("run-httpd");

    let mak_missing =
        ACCESS_KEY.get().unwrap(/* safe while it's init'd at the beginning of main */).is_none();

    // When MEL is built with the `mcp` feature, pass MCP_ENABLED to Apache to
    // enable the /mcp proxypass.
    #[cfg(feature = "mcp")]
    httpd_cmd.env("MCP_ENABLED", "true");

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
        .map_err(|_e| MelError::HttpdProcessFailed)?
        .wait()
        .map_err(|_e| MelError::HttpdProcessFailed)
}

/// Print a missing MAK warning with remediation instructions, and a slow countdown before
/// continuing.
fn missing_mak_slow_warn() {
    eprintln!("Warning: Missing ACCESS_KEY; Please retrieve an ACCESS_KEY from https://access.redhat.com/offline/access and provide it in the ACCESS_KEY environment variable to enable Solutions and Articles (Red Hat Knowledge Base content). CVEs, errata, product documentation, and search remain available without an access key.");
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
///
/// When `protected_available` is true, the encrypted `portal-protected` collection has been
/// decrypted and unpacked, so Solr is told to search across both collections via the
/// `MIMIR_SEARCH_SHARDS` env var (forwarded by `run-solr` as `-Dmimir.search.shards`).  When
/// false, only the unencrypted `portal` collection is searched.
fn start_solr(protected_available: bool) {
    // Start solr in the background
    std::thread::spawn(move || {
        let mut cmd = Command::new("run-solr");
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        if protected_available {
            cmd.env("MIMIR_SEARCH_SHARDS", MIMIR_SEARCH_SHARDS);
        }
        match cmd.spawn() {
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

/// Block until every Solr core that will be queried answers its ping handler, or until
/// [`SOLR_READINESS_TIMEOUT`] elapses.
///
/// Solr's HTTP listener (started by `run-solr`) accepts connections well before its cores finish
/// loading, and the encrypted `portal-protected` collection must additionally be decrypted and
/// unpacked first.  Because the `portal` `/select` handler distributes across both cores, a search
/// that arrives during that window receives an HTTP 503 ("SolrCore is loading") that Apache proxies
/// straight through to the browser -- the first-search error seen in the access log.  Gating httpd
/// startup on core readiness closes that race.
///
/// If the timeout elapses we return anyway and let httpd start: a degraded launch that self-heals
/// on retry is preferable to never serving the site, matching MEL's limited-launch philosophy for
/// other failure modes.
fn wait_for_solr_ready(protected_available: bool) {
    let mut cores: Vec<&str> = vec!["portal"];
    if protected_available {
        cores.push("portal-protected");
    }

    debug_println!("MEL: waiting for Solr cores to become ready: {cores:?}");

    let deadline = Instant::now() + SOLR_READINESS_TIMEOUT;
    while !cores.iter().all(|core| solr_core_ready(core)) {
        if Instant::now() >= deadline {
            eprintln!(
                "Warning: Solr cores were not all ready after {}s; starting httpd anyway. The first search may need a retry.",
                SOLR_READINESS_TIMEOUT.as_secs()
            );
            return;
        }
        std::thread::sleep(SOLR_READINESS_POLL_INTERVAL);
    }

    debug_println!("MEL: all Solr cores are ready");
}

/// Probe a single Solr core's ping handler over a raw TCP HTTP/1.0 request.
///
/// Returns `true` only when the core answers HTTP 200, which for the ping handler means the core is
/// loaded and its searcher is registered.  A connection error, timeout, or non-200 status (e.g. the
/// 503 returned while the core is still loading) yields `false`.  Implemented with `std::net` so MEL
/// takes on no HTTP-client dependency and relies on no external binary (curl/wget may be absent from
/// the image).  The ping handler is used rather than `/select` because it does not self-distribute
/// across shards, so it reports the readiness of exactly this one core.
fn solr_core_ready(core: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(SOLR_ADDR) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(SOLR_PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOLR_PROBE_TIMEOUT));

    let request = format!(
        "GET /solr/{core}/admin/ping?wt=json HTTP/1.0\r\nHost: {SOLR_ADDR}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    // We only need the status line; read what the server sends and inspect the first line.
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }

    // The status line looks like "HTTP/1.1 200 OK"; a ready core returns 200, a loading or
    // unavailable core returns 503.
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .is_some_and(|status_line| status_line.contains(" 200 "))
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
