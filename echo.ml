
let cert_path = "/tmp/tls_cert.pem"
let key_path = "/tmp/tls_key.pem"
(*
let cert_path = "../TLS-Attacker/resources/rsa1024cert.pem"
let key_path = "../TLS-Attacker/resources/rsa1024key.pem"
*)

let port = 4433


let add_to_session_cache cache tls =
  match Tls.Engine.epoch tls with
  | `InitialEpoch -> ()
  | `Epoch epoch -> Hashtbl.replace cache epoch.session_id epoch

let handle_tls tls input =
  let tls_return = Tls.Engine.handle_tls tls input in
  let response = begin match tls_return with
    | `Fail (_, `Response response)
    | `Ok (_, `Response Some response, _) ->
      response
    | _ -> Cstruct.create 0
  end in
  let reply = begin match tls_return with
    | `Ok (_, _, `Data Some data) ->
      prerr_endline "====================== data ======================";
      prerr_endline @@ Cstruct.to_string data;
      prerr_endline "==================================================";
      data
    | _ -> Cstruct.create 0
  end in
  let response, state = begin match tls_return with
    | `Ok (`Ok new_tls, _, _) ->
      if Cstruct.len reply = 0 then
        response, `Repeat new_tls
      else
        begin match Tls.Engine.send_application_data new_tls [reply] with
          | None -> prerr_endline "send application data failed"; response, `Repeat new_tls
          | Some (new_new_tls, response') ->
            Cstruct.concat [response; response'], `Repeat new_new_tls
        end
    | `Ok (`Eof, _, _) ->
      prerr_endline "Got tls eof"; response, `Close
    | `Ok (`Alert alert, _, _) ->
      Printf.eprintf "Got alert: %s\n%!" @@ Tls.Packet.alert_type_to_string alert;
      response, `Close
    | `Fail (`Error _ as error, _) ->
      Printf.eprintf "Got error: %s\n%!" @@ Tls.Engine.string_of_failure error;
      response, `Close
    | `Fail (`Fatal _ as fatal, _) ->
      Printf.eprintf "Got fatal: %s\n%!" @@ Tls.Engine.string_of_failure fatal;
      response, `Close
  end in
  response, state

let rec server_loop (socket, tls, buffer, session_cache) =
  let len = Unix.read socket buffer 0 (Bytes.length buffer) in
  if len = 0 then
    prerr_endline "Got unix eof"
  else begin
    assert (len > 0);
    let cstruct = Cstruct.of_bytes (Bytes.sub buffer 0 len) in
    let response, state = handle_tls tls cstruct in
    begin if Cstruct.len response > 0 then
        let bytes = Cstruct.to_string response |> Bytes.unsafe_of_string in
        let length_written = Unix.write socket bytes 0 (Bytes.length bytes) in
        assert (length_written = Bytes.length bytes);
    end;
    match state with
    | `Repeat new_tls ->
      add_to_session_cache session_cache new_tls;
      server_loop (socket, new_tls, buffer, session_cache)
    | `Close -> ()
  end

let main () =
  Nocrypto_entropy_unix.initialize ();

  let cert_data = CCIO.File.read_exn cert_path in
  let key_data = CCIO.File.read_exn key_path in

  let cert = X509.Encoding.Pem.Certificate.of_pem_cstruct1 @@ Cstruct.of_string cert_data in
  let (`RSA key) = X509.Encoding.Pem.Private_key.of_pem_cstruct1 @@ Cstruct.of_string key_data in
  let ciphers = [
           `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
         ; `TLS_DHE_RSA_WITH_AES_128_CBC_SHA
         ; `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
         ; `TLS_DHE_RSA_WITH_AES_128_CCM
         ; `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
         ; `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
         ; `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
         ; `TLS_DHE_RSA_WITH_AES_256_CCM
         ; `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
         ; `TLS_RSA_WITH_3DES_EDE_CBC_SHA
         ; `TLS_RSA_WITH_AES_128_CBC_SHA
         ; `TLS_RSA_WITH_AES_128_CBC_SHA256
         ; `TLS_RSA_WITH_AES_128_CCM
         ; `TLS_RSA_WITH_AES_128_GCM_SHA256
         ; `TLS_RSA_WITH_AES_256_CBC_SHA
         ; `TLS_RSA_WITH_AES_256_CBC_SHA256
         ; `TLS_RSA_WITH_AES_256_CCM
         ; `TLS_RSA_WITH_AES_256_GCM_SHA384
         ; `TLS_RSA_WITH_RC4_128_MD5
         ; `TLS_RSA_WITH_RC4_128_SHA ] in
  let hashes = [ `MD5 ; `SHA1 ; `SHA224 ; `SHA256 ; `SHA384 ; `SHA512 ] in
  let version = (Tls.Core.TLS_1_0, Tls.Core.TLS_1_2) in

  let use_session_cache = false in
  let cache = Hashtbl.create 1024 in
  let session_cache =
    if use_session_cache then
      Some (fun key -> CCHashtbl.get cache key)
    else
      None
  in

  let reneg = true in

  let use_authenticator = false in
  let authenticator =
    if use_authenticator then
      (* Bad authenticator *)
      Some X509.Authenticator.null
    else
      None
  in

  let config = Tls.Config.server
      ?session_cache ~version ~ciphers
      ~hashes ~reneg ~certificates:(`Single ([cert], key)) ?authenticator () in
  let tls = Tls.Engine.server config in

  let address = Unix.inet_addr_loopback in
  let server_socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt server_socket Unix.SO_REUSEADDR true;

  Unix.bind server_socket (Unix.ADDR_INET (address, port));
  Unix.listen server_socket 1;

  let buffer = Bytes.create (1024 * 1024) in

  while true do
    Printf.eprintf "Accepting on port %d ...\n%!" port;
    let socket, source_address = Unix.accept server_socket in
    prerr_endline "Got connection";
    prerr_endline "================================================================================";
    server_loop (socket, tls, buffer, cache);
    Unix.close socket;
    prerr_endline "Connection closed";
  done

let () = main ()
