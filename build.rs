fn main() {
    // Build src/cilium/tetragon.rs based on the protobuf files in
    // "../../src/tetragon/api".
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        // Call output directory Cilium because it's a Cilium API and we
        // expect them to keep their namespace free of conflicts with
        // their other projects.
        .out_dir("src/cilium")
        // Needed for newer tetragon API (between 5ac805fab..24fcb1546).
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &[
                "../../src/tetragon/api/v1/tetragon/events.proto",
                "../../src/tetragon/api/v1/tetragon/sensors.proto",
            ],
            &["../../src/tetragon/api/v1"], // root proto path
        )
        .unwrap();
}
