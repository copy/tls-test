open Solvuu_build.Std

let project_name = "echo_server"

let app = Project.app project_name
    ~thread:()
    ~safe_string:()
    ~bin_annot:()
    ~short_paths:()
    ~g:()
    ~w:"A-4-40-41-42-44-45-26-27"
    ~internal_deps:[]
    ~findlib_deps:[
      "tls";
      "cstruct";
      "containers";
      "nocrypto";
      "nocrypto.unix";
    ]
    ~file:"echo.ml"

let () = Project.basic1 ~project_name ~version:"dev" [app]
