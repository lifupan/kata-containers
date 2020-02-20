//use nix::unistd::{self, ForkResult, Gid, Pid, Uid};
use encoding::all::ISO_8859_1;
use encoding::{EncoderTrap, Encoding};
use protocols::oci::Process as OCIProcess;
use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::env;

pub fn setup_env(f: &mut File, process: &OCIProcess) {
    let fs_path = Path::new("/etc/profile.d");
    if !fs_path.exists() {
        fs::create_dir_all(fs_path)
            .map_err(|err| writeln!(f, "failed to create /etc/profile.d: {}", err));
    }

    let mut data = "".to_string();
    let mut data_iso = "".to_string();
    let mut has_term = false;
    // setup env file
    for env in process.Env.iter() {
        let mut splits: Vec<&str> = env.splitn(2, "=").collect();
        if splits.len() == 1 {
            splits.push("");
        }
        let mut value = splits[1].to_string().clone();
        if splits[0] == "PATH" {
            value += ":$PATH";
        } else if splits[0] == "TERM" {
            has_term = true;
        }
        env::set_var(splits[0], &value);
        data += &format!("export {}=\"{}\"\n", splits[0], value);
        data_iso += &format!("env_{} = {}\n", splits[0], value);
    }

    if !has_term {
        env::set_var("TERM", "xterm");
        data += &format!("export {}=\"{}\"\n", "TERM", "xtrem");
    }

    let env_file = Path::new(fs_path).join("pouchenv.sh");
    fs::write(env_file, data.as_str())
        .map_err(|err| writeln!(f, "failed to create pouchenv.sh: {}", err));

    // keep envs in properties file. As java properties files are ISO-8859-1 encoded.
    let iso_file = "/etc/instanceInfo";
    let iso_byte: Vec<u8> = ISO_8859_1.encode(&data_iso, EncoderTrap::Strict).unwrap();
    fs::write(iso_file, iso_byte)
        .map_err(|err| writeln!(f, "failed to create /etc/instanceInfo: {}", err));
}

pub fn init_script(process: &mut OCIProcess) {
    let mut log_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open("/agent.log")
        .unwrap();

    setup_env(&mut log_file, process);

    // touch rpm (because an overlay bug: https://github.com/docker/for-linux/issues/72)
    if Path::new("/var/lib/rpm").exists() {
        Command::new("sh")
            .arg("-c")
            .arg("touch /var/lib/rpm/*")
            .output();
    }

    if Path::new("/var/spool/cron").exists() {
        Command::new("sh")
            .arg("-c")
            .arg("touch /var/spool/cron/*")
            .output();
    }

    let mut script_vec: Vec<&str> = vec![];

    if Path::new("/etc/after_start.sh").exists() {
        script_vec.push("/etc/after_start.sh")
    }

    let add_script = get_env(process.Env.to_vec(), "InitScript");
    if add_script != "" {
        script_vec.push(add_script.as_str());
    }

    // script should run with uid 0 (root user)
    for script in script_vec.iter() {
        writeln!(log_file, "execute scirpt {}", &script);
        // fork a child process to execute script
        match Command::new(&script).spawn() {
            Ok(mut child) => {
                child.wait();
            }
            Err(e) => (),
        }
    }

    let run_mode = get_env(process.Env.to_vec(), "ali_run_mode");
    if (run_mode == "vm" || run_mode == "common_vm") && process.Args.len() > 0 {
        writeln!(log_file, "run common_vm");
        let mut args: Vec<String> = Vec::new();
        for ag in process.Args.iter() {
            args.push(ag.to_string());
        }

        // in this case, the exec environment is t4
        let mut user_cmd = args.join(" ");
        if process.Cwd.len() > 0 {
            user_cmd = "cd".to_string() + &process.Cwd + "\n" + &user_cmd;
        }

        let mut target = "/etc/rc3.d/S81common_vm";
        if !Path::new(target).exists() {
            target = "/etc/rc.d/rc.local"
        }

        match File::open(&target) {
            Ok(f) => {
                let reader = BufReader::new(f);
                let mut output = "".to_string();
                for line in reader.lines() {
                    let l_str = line.unwrap_or("".to_string());
                    if l_str == "#######entrypoint####" {
                        output = output + &l_str + "\n";
                        break;
                    } else {
                        output = output + &l_str + "\n";
                    }
                }

                output = output + "\n" + &user_cmd;

                writeln!(log_file, "change target file {}: {}", target, &output);

                fs::write(target, output.as_bytes())
                    .map_err(|err| writeln!(log_file, "failed to write {}: {}", target, err));

                // reset args
                let re_args: Vec<String> = vec!["/sbin/init".to_string()];
                process.set_Args(::protobuf::RepeatedField::from_vec(re_args));
            }
            Err(err) => {
                writeln!(log_file, "failed to open target file {}: {}", target, err);
            }
        }
    }
}

fn get_env(envs: Vec<String>, key: &str) -> String {
    for e in envs.iter() {
        let splits: Vec<&str> = e.splitn(2, "=").collect();
        if splits[0] == key {
            return splits[1].to_string();
        }
    }

    "".to_string()
}
