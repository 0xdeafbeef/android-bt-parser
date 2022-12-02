use std::borrow::Cow;
use std::path::PathBuf;

use addr2line::{gimli, Location};
use addr2line::fallible_iterator::FallibleIterator;
use addr2line::gimli::{EndianRcSlice, RunTimeEndian};
use addr2line::object::{Object, SymbolMap, SymbolMapName};
use anyhow::Context;
use chrono::FixedOffset;
use clap::Parser as _;
use regex::Regex;

#[derive(clap::Parser, Debug)]
struct App {
    #[clap(short, long)]
    device_id: String,

    #[clap(short, long)]
    lib_path: PathBuf,

    #[clap(short, long)]
    app_name: String,
}

fn main() -> anyhow::Result<()> {
    let args = App::parse();

    let output = std::process::Command::new("adb")
        .arg("-s")
        .arg(&args.device_id)
        .arg("logcat")
        .arg("-d")
        .arg("-v")
        .arg("printable")
        .output()
        .context("Failed to execute logcat command")?;

    if !output.status.success() {
        anyhow::bail!("Failed to execute logcat command");
    }

    let stdout = String::from_utf8(output.stdout).context("Failed to parse logcat output")?;

    let mut parser = Parser::new(&stdout, &args.app_name);

    let lib_data = std::fs::read(args.lib_path).context("Failed to read lib file")?;
    let lib = Lib::new(&lib_data)?;

    while let Some(parsed) = parser.parse() {
        println!("\nShowing info for {}", parsed.datetime);
        for address in parsed.function_addresses {
            lib.look_up(address)?;
        }
    }

    Ok(())
}

struct Parser<'a, 'b> {
    data: &'a str,
    pos: usize,
    package_name: &'b str,
}

impl<'a, 'b> Parser<'a, 'b> {
    pub fn new(text: &'a str, package_name: &'b str) -> Self {
        Self {
            data: text,
            pos: 0,
            package_name,
        }
    }

    pub fn parse(&mut self) -> Option<ParsedData> {
        if self.pos >= self.data.len() {
            return None;
        }
        let mut logs = Vec::new();

        let mut is_inside_log = false;
        let mut is_our_app = false;
        let mut datetime = None;

        let regex = Regex::new(r"#[0-9]+ pc ([0-9a-f]+)  /").unwrap();
        let lines = self.data[self.pos..].lines();

        for line in lines {
            self.pos += line.len() + 1;
            if line.contains("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***") {
                is_inside_log = true;
                continue;
            }

            if is_inside_log {
                if line.contains("Cmdline:") {
                    let parts = line.split("Cmdline:").last()?.trim().to_owned();
                    if parts.contains(self.package_name) {
                        is_our_app = true;
                    }
                }

                if line.contains("Timestamp:") {
                    let timestamp = line.split("Timestamp:").last()?.trim().to_owned();
                    // 2022-12-02 22:03:33.079489977+0100
                    datetime = Some(
                        chrono::DateTime::parse_from_str(&timestamp, "%Y-%m-%d %H:%M:%S%.9f%z")
                            .unwrap(),
                    );
                }

                if is_our_app {
                    if let Some(c) = regex.captures(line) {
                        if let Some(addr) = c.get(1) {
                            let address = u64::from_str_radix(addr.as_str(), 16).unwrap();
                            logs.push(address);
                        }
                    } else if !logs.is_empty() {
                        break;
                    }
                }
            }
        }

        Some(ParsedData {
            datetime: datetime?,
            function_addresses: logs,
        })
    }
}



#[derive(Debug)]
struct ParsedData {
    datetime: chrono::DateTime<FixedOffset>,
    function_addresses: Vec<u64>,
}


struct Lib<'a> {
    context: addr2line::Context<EndianRcSlice<RunTimeEndian>>,
    symbol_map: SymbolMap<SymbolMapName<'a>>,
}

impl <'a>Lib<'a> {
    pub fn new(file: &'a [u8]) -> anyhow::Result<Lib<'a>> {
        let object = addr2line::object::read::File::parse(file)?;
        let symbol_map: SymbolMap<SymbolMapName> = object.symbol_map();

        let context =
            addr2line::Context::new(&object)?;

        Ok(Self { context, symbol_map })
    }

    pub fn look_up(&self, address: u64) -> anyhow::Result<()> {
        let mut frames = self.context.find_frames(address)?.enumerate();

        while let Some((i, frame)) = frames.next()? {
            if i != 0 {
                print!(" (inlined by) ");
            }

            if let Some(func) = frame.function {
                print_function(
                    func.raw_name().ok().as_ref().map(AsRef::as_ref),
                    func.language,
                );
            } else {
                let name = find_name_from_symbols(&self.symbol_map, address);
                print_function(name, None);
            }


            print!(" at ");


            print_loc(frame.location.as_ref());
        }

        Ok(())
    }
}

fn find_name_from_symbols<'a>(
    symbols: &'a SymbolMap<SymbolMapName>,
    probe: u64,
) -> Option<&'a str> {
    symbols.get(probe).map(|x| x.name())
}

fn print_function(name: Option<&str>, language: Option<gimli::DwLang>) {
    if let Some(name) = name {
        print!("{}", addr2line::demangle_auto(Cow::from(name), language));
    } else {
        print!("??");
    }
}

fn print_loc(loc: Option<&Location>) {
    if let Some( loc) = loc {
        if let Some(ref file) = loc.file.as_ref() {
            print!("{}:", file);
        } else {
            print!("??:");
        }
        print!("{}:{}", loc.line.unwrap_or(0), loc.column.unwrap_or(0));

        println!();

        println!("??:0:0");
    }
}

#[cfg(test)]
mod test {
    use super::Parser;

    const TEST_OUTPUT: &str = r#"
    *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
    Build fingerprint: 'google/raven/raven:13/TP1A.221105.002/9080065:user/release-keys'
    Revision: 'MP1.0'
    ABI: 'arm64'
    Timestamp: 2022-12-02 22:03:33.079489977+0100
    Process uptime: 26s
    Cmdline: com.broxus.crystal.app
    pid: 6401, tid: 6801, name: nekoton_flutter  >>> com.broxus.crystal.app <<<
                                uid: 10466
    tagged_addr_ctrl: 0000000000000001 (PR_TAGGED_ADDR_ENABLE)
    signal 6 (SIGABRT), code -1 (SI_QUEUE), fault addr --------
    x0  0000000000000000  x1  0000000000001a91  x2  0000000000000006  x3  0000007ab223b270
    x4  3963646b6860651f  x5  3963646b6860651f  x6  3963646b6860651f  x7  7f7f7f7f7f7f7f7f
    x8  00000000000000f0  x9  0000007e2d3069e0  x10 0000000000000001  x11 0000007e2d3475e0
    x12 0000000000000019  x13 0000007ab223b1d3  x14 0000000000003038  x15 0000007ab223b1b8
    x16 0000007e2d3b4d58  x17 0000007e2d390120  x18 0000007ab0b36000  x19 0000000000001901
    x20 0000000000001a91  x21 00000000ffffffff  x22 00005a636363634d  x23 b400007c4ba6a4d0
    x24 0000000000000001  x25 0000007ab3d762b0  x26 b400007c4ba6a4d0  x27 0000000000000000
    x28 0000007ab3d762b0  x29 0000007ab223b2f0
    lr  0000007e2d3380c8  sp  0000007ab223b250  pc  0000007e2d3380f4  pst 0000000000001000
    backtrace:
    #00 pc 00000000000530f4  /apex/com.android.runtime/lib64/bionic/libc.so (abort+164) (BuildId: cbc4c62a9b269839456f1d7728d8411e)
    #01 pc 00000000006dcda8  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #02 pc 00000000006d7f68  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #03 pc 00000000006d99ac  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #04 pc 00000000006eea30  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #05 pc 00000000006eea24  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #06 pc 00000000006eea18  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #07 pc 00000000006225ac  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #08 pc 00000000002d7b74  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #09 pc 00000000003e3240  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #10 pc 0000000000300260  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #11 pc 000000000024554c  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #12 pc 000000000062bdd8  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #13 pc 000000000062b734  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #14 pc 000000000063da74  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #15 pc 000000000062b2ac  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #16 pc 000000000063b254  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #17 pc 000000000062c844  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #18 pc 0000000000636c38  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #19 pc 000000000063c0bc  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #20 pc 00000000006338c4  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #21 pc 00000000006dca44  /data/app/~~GJe1gxYXui4o0bMuaGH4kQ==/com.broxus.crystal.app-glHCxmoIdHDB6a0WNrUrfA==/base.apk
    #22 pc 00000000000c14dc  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+204) (BuildId: cbc4c62a9b269839456f1d7728d8411e)
    #23 pc 0000000000054930  /apex/com.android.runtime/lib64/bionic/libc.so (__start_thread+64) (BuildId: cbc4c62a9b269839456f1d7728d8411e)
    "#;

    #[test]
    fn test_parse_single() {
        let mut parser = Parser::new(&TEST_OUTPUT, "com.broxus.crystal.app");
        let ints = parser.parse().unwrap();
        dbg!(ints);
    }

    #[test]
    fn test_parse_multi() {
        let text = format!("{}{}{}", TEST_OUTPUT, TEST_OUTPUT, TEST_OUTPUT);

        let mut parser = Parser::new(&text, "com.broxus.crystal.app");
        let ints = parser.parse().unwrap();
        dbg!(ints);
        let ints = parser.parse().unwrap();
        dbg!(ints);
        let ints = parser.parse().unwrap();
        dbg!(ints);
    }
}
