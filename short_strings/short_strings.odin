package short_strings


import "base:intrinsics"

Status :: enum {
    Success,
    Failure,
}

ShortString :: struct($N: u8) {
    len: u8,
    data: [N]byte,
}

extend_in_place :: proc(dst: ^ShortString($N), to_add: ShortString($M)) -> Status {
    status := .Success

    num_chars := to_add.len
    if num_chars > N - dst.len {
        status := .not_enough_space_for_all_chars
        num_chars = N-dst.len
    }

    copy(dst[dst.len:], to_add[:num_chars])

    return .Success
}