use chrono::DateTime;
use hyper_util::rt::TokioIo;
use prost_types::FieldMask;
use prost_types::Timestamp;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use std::process::exit;

mod cilium;
use cilium::api::v2::tetragon::{
    fine_guidance_sensors_client::FineGuidanceSensorsClient as TetragonClient,
    get_events_response::Event,
    GetEventsRequest,
    EventType,
    Filter,
    FieldFilter,
    FieldFilterAction,
};

const GIT_VERSION: &str = git_version::git_version!();

const TETRAGON_ADDR: &str = "/run/tetragon/tetragon.sock";

const NULL_PID: u32 = u32::MAX;
const NULL_UID: u32 = u32::MAX;
const NULL_TIMESTAMP: Timestamp = Timestamp{ seconds: 0, nanos: 0 };


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("tetrars {GIT_VERSION} started");

    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(|_: Uri| async {
            let path = TETRAGON_ADDR;

            // Connect to a Uds socket
            Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))
        }))
        .await?;

    let mut client = TetragonClient::new(channel);

    // tetra getevents
    //   -e PROCESS_EXEC,PROCESS_KPROBE
    //   -f process.pid,process.uid,process.auid,process.cwd,process.binary,
    //      process.arguments,process.process_credentials,process.binary_properties,
    //      parent.pid,parent.binary,parent.cwd,
    //      function_name,args,action,policy_name
    let request = tonic::Request::new(GetEventsRequest {
        allow_list: vec![
            Filter {
                event_set: vec![
                    // Listen for Exec events. Do we want ProcessExit events too?
                    EventType::ProcessExec.into(),
                    // TODO: Choose whether to re-enable ProcessKprobe.
                    //EventType::ProcessKprobe.into(),
                ],
                ..Default::default()
            },
        ],
        field_filters: vec![
            // Field filters for ProcessExec.
            FieldFilter {
                event_set: vec![EventType::ProcessExec.into()],
                fields: Some(FieldMask {
                    paths: vec![
                        "process.pid".to_string(),
                        "process.auid".to_string(),
                        "process.uid".to_string(),
                        "process.cwd".to_string(),
                        "process.binary".to_string(),
                        // FIXME: Arguments are an ugly string and not at all
                        // a nice execve() array. This is a tetragon
                        // (probably eBPF) limitation.
                        "process.arguments".to_string(),
                        // FIXME: The process_credentials are unused at
                        // the moment, so we can skip them. But they do
                        // contain nice fine-grained uid-info.
                        //"process.process_credentials".to_string(),
                        // FIXME: We may want to re-enable the
                        // binary_properties later on. It looks like they
                        // should be set for setuid binaries.
                        //"process.binary_properties".to_string(),
                        // NOTE: The "flags" property looks interesting, but
                        // according to the docs, it is not reliable.
                        //   flags: "",
                        //   flags: "execve",
                        //   flags: "execve clone",
                        //   flags: "execve rootcwd",
                        //   flags: "execve rootcwd clone",
                        //   flags: "procFS",
                        //   flags: "procFS auid rootcwd",
                        "process.flags".to_string(),
                        "parent.pid".to_string(),
                        "parent.auid".to_string(),
                        "parent.uid".to_string(),
                        "parent.cwd".to_string(),
                        "parent.binary".to_string(),
                    ],
                }),
                action: FieldFilterAction::Include.into(),
                ..Default::default()
            },
            // Field filters for ProcessKprobe.
            FieldFilter {
                event_set: vec![EventType::ProcessKprobe.into()],
                fields: Some(FieldMask {
                    paths: vec![
                        "function_name".to_string(),
                        "args".to_string(),
                        "action".to_string(),
                        "policy_name".to_string(),
                    ],
                }),
                action: FieldFilterAction::Include.into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    });

    let mut stream = client.get_events(request).await?.into_inner();

    while let Some(event) = stream.message().await? {
        match event.event {
            Some(Event::ProcessExec(process_exec)) => {
                match (process_exec.process, process_exec.parent) {
                    (Some(process), Some(parent)) => {
                        //let auid: i64 = process.auid.map(|x| x as i64).unwrap_or(-1);
                        let auid = process.auid.unwrap_or(NULL_UID);
                        let pauid = parent.auid.unwrap_or(NULL_UID);
                        if (1000..=9999).contains(&auid) || (1000..=9999).contains(&pauid) {
                            let pid = process.pid.unwrap_or(NULL_PID);
                            let uid = process.uid.unwrap_or(NULL_UID);
                            let cwd = to_js_string(process.cwd);
                            let binary = to_js_string(process.binary);

                            let flags = process.flags; // "execve rootcwd clone"

                            let mut arguments = process.arguments;
                            if flags.contains("trunc") {
                                eprintln!("WARN: flags with truncation: {flags}");
                                if flags.contains("truncArgs") {
                                    arguments = "ERROR_flags_truncArgs\"".to_string()
                                }
                            };
                            arguments = to_js_string(ensure_within::<40_000>(&arguments));

                            let ppid = parent.pid.unwrap_or(NULL_PID);
                            let puid = parent.uid.unwrap_or(NULL_UID);
                            let pcwd = to_js_string(parent.cwd);
                            let pbinary = to_js_string(parent.binary);
                            let node_name = to_js_string(event.node_name);
                            let time = to_js_timestamp(&event.time.unwrap_or(NULL_TIMESTAMP));
                            println!("\
{{\"process_exec\":{{\"process\":{{\
\"pid\":{pid}, \"uid\":{uid}, \"cwd\":{cwd}, \"binary\":{binary}, \
\"arguments\":{arguments}, \"auid\":{auid}\
}}, \"parent\":{{\
\"pid\":{ppid}, \"uid\":{puid}, \"cwd\":{pcwd}, \"binary\":{pbinary}, \
\"auid\":{pauid}\
}}}}, \"node_name\":{node_name}, \"time\":{time}}}");
                        }
                    },
                    (Some(process), None) => {
                        //let auid: i64 = process.auid.map(|x| x as i64).unwrap_or(-1);
                        let auid = process.auid.unwrap_or(NULL_UID);
                        if (1000..=9999).contains(&auid) {
                            let pid = process.pid.unwrap_or(NULL_PID);
                            let uid = process.uid.unwrap_or(NULL_UID);
                            let cwd = to_js_string(process.cwd);
                            let binary = to_js_string(process.binary);
                            let arguments = to_js_string(process.arguments);
                            let node_name = to_js_string(event.node_name);
                            let time = to_js_timestamp(&event.time.unwrap_or(NULL_TIMESTAMP));
                            println!("\
{{\"process_exec\":{{\"process\":{{\
\"pid\":{pid}, \"uid\":{uid}, \"cwd\":{cwd}, \"binary\":{binary}, \
\"arguments\":{arguments}, \"auid\":{auid}\
}}}}, \"node_name\":{node_name}, \"time\":{time}}}");
                        }
                    },
                    (None, maybe_parent) => {
                        eprintln!("\
UNHANDLED: no process but parent? None / {maybe_parent:#?}");
                    }

                }
            },
            Some(Event::ProcessKprobe(_)) => {
                // TODO: Implement this, if we re-enable ProcessKprobe.
                eprintln!("UNHANDLED: kprobe: {event:#?}");
            },
            _ => todo!(),
        }
    }

    eprintln!("UNHANDLED: EOF");
    exit(1);
}

fn to_js_string<S: AsRef<str>>(s: S) -> String {
    serde_json::to_string(s.as_ref()).unwrap()
}

fn to_js_timestamp(ts: &Timestamp) -> String {
    let dt = DateTime::from_timestamp(ts.seconds, 0).unwrap();
    format!("\"{}.{:09}Z\"", dt.format("%Y-%m-%dT%H:%M:%S"), ts.nanos)
}

/// Usage: let s = ensure_within::<255>(possibly_long_string)
/// TODO: This truncates to characters, but likely the buffer limit is
/// in bytes, not characters. That would mean that we would end up with
/// issues if the arguments are non-ascii UTF-8.
/// NOTE: Right now, the buffer we're facing is JOURNALD_LINEMAX, which
/// is 48 * 1024 = 49152. By trimming the largest message to 40_000 we
/// have plenty of room to spare.
fn ensure_within<const N: usize>(s: &str) -> String {
    const TRUNC_MSG: &str = "[...truncated]";

    if s.len() > N {
        eprintln!("WARN: input of length {} truncated to {}", s.len(), N);
        let truncated_len = N.saturating_sub(TRUNC_MSG.len());
        let mut out = s[..truncated_len].to_string();
        out.push_str(TRUNC_MSG);
        out
    } else {
        s.to_string()
    }
}
