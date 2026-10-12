/// Filler that keeps stored properties off a contended cache line. Swift lays
/// out class properties in declaration order, so a pad between two groups
/// puts them on different lines (128 bytes: adjacent-line prefetch pairs
/// 64-byte lines on x86).
struct Pad112 {
    private var bytes: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                        UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)
        = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

struct Pad128 {
    private var bytes: (Pad112, UInt64, UInt64) = (Pad112(), 0, 0)
}
