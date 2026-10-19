package EzPassMan_Server

import "core:crypto"
import "core:net"
import "core:fmt"
import "core:crypto/noise"
import "core:encoding/endian"
import "core:mem"
import "core:runtime"

import noise_net"noise_networking"
import ss "../smallstrings"
import crypto_core "../ezpassman_crypto_core"

EzString :: ss.SmallString(255)

RequestType :: enum u8 {
    NewUser = 1,
    FetchVault = 2,
    DeleteVault = 3,
    UpdateVault = 4,
    Error = 255,
}

Request :: struct {
    kind: RequestType,
    user_id: EzString,
    auth_token: u64,
}

parse_request :: proc(data: []u8) -> Request {
    user_id, succeeded := ss.from_slice(data[1 : 257], 255)
    auth_token, endian_success := endian.get_u64(data[257 : 257+8], .Little)
    kind: RequestType
    switch data[0] {
        case 1: kind = .NewUser
        case 2: kind = .FetchVault
        case 3: kind = .DeleteVault
        case 4: kind = .UpdateVault
        case: kind = .Error
    }
    request := Request{
        kind = kind,
        user_id = user_id,
        auth_token = auth_token,
    }

    return request
}

main :: proc() {

    vaults := make(map[EzString]crypto_core.Vault)

    fmt.println("Starting...")
    server_address, parsed := net.parse_endpoint("127.0.0.1:5000")
    fmt.println("Parsed endpoint...")
    if !parsed {
        panic("PARSING WRONG!!")
    }
    listener, listen_err := net.listen_tcp(server_address)
    fmt.println("Opened listener...")

    server_should_keep_running := true

    for server_should_keep_running {
        socket, peer, status := net.accept_tcp(listener) // Blocks server until connection is available
        hs : noise.Handshake_State
        hs_status := noise.handshake_init(&hs, false, nil, nil, nil, noise_net.DEFAULT_PROTOCOL_NAME)
        connection, connection_status := noise_net.establish_connection_all_the_way(socket, peer)
        data, nonce, data_status := noise_net.receive_data(&connection, expected_len = size_of(Request))
        if data_status != .ok {
            fmt.println("Status: ", data_status)
            return
        }
        request := parse_request(data)

        switch request.kind {
            case .NewUser: {
                unverified_vault, nonce, new_user_status := noise_net.receive_data(&connection, expected_len = size_of(EzString) + size_of(crypto_core.Vault))
                if new_user_status != .ok {
                    continue
                }
                user_id := unverified_vault[:size_of(EzString)]
                vault_handle, verification_status := crypto_core.blob_to_vault(unverified_vault[size_of(EzString):])
                if verification_status != .Success {
                    continue
                } else {
                }

            }
            case .FetchVault: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
            case .DeleteVault: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
            case .UpdateVault: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
            case .Error: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
        }
        
        // connection_status : noise_net.ConnectionStatus = .handshake_pending
        // connection : noise_net.Connection
        // for  {
        //     connection, connection_status = noise_net.establish_connection_step(&hs, socket, server_address)
        //     if connection_status == .handshake_pending {
        //         continue
        //     } else if connection_status == .handshake_complete {
        //         data, nonce, recv_status := noise_net.receive_data(&connection)
        //         fmt.println("Recv status: ", recv_status)
        //         fmt.println("NONCE: ", nonce)
        //         fmt.println(data)
                
        //         fmt.println("SUCCESS!!")
        //         break
        //     } else {
        //         fmt.println(connection_status)
        //         break
        //     }
        // }
    }
        
}