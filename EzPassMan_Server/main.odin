package EzPassMan_Server


import "core:crypto/noise"
import "core:net"


establish_connection :: proc()


main :: proc() {
    hs : noise.Handshake_State
    hs_status := noise.handshake_init(&hs, false, nil, nil, nil, "Noise_XX_25519_AESGCM_SHA256")


}