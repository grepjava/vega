import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// A test run under many schedules: each on a fresh `Runtime.seeded`
/// runtime, which picks the order its tasks run in from the seed. A race
/// that one interleaving in a thousand shows comes up in a run of a few
/// hundred seeds, and the seed it failed with brings it back every time.
///
/// ```swift
/// @Test func handoffNeverLosesAValue() throws {
///     try Simulation.run(seeds: 0..<500) { rt in
///         let ch = MPSCChannel<Int>(capacity: 1)
///         ...
///         #expect(...)   // or throw
///     }
/// }
/// ```
///
/// `VEGA_SEED=n` in the environment runs seed n alone, to reproduce one.
public enum Simulation {
    /// Why a seeded run failed: the seed, and the error `body` threw.
    public struct Failure: Error, CustomStringConvertible {
        public let seed: UInt64
        public let error: any Error

        public var description: String {
            "failed with seed \(seed) (rerun with VEGA_SEED=\(seed)): \(error)"
        }
    }

    /// Run `body` once per seed, each on its own seeded runtime, until one
    /// throws; that one is rethrown as a `Failure` naming its seed.
    /// Returns what each run returned.
    @discardableResult
    public static func run<T: Sendable>(
        seeds: Range<UInt64> = 0..<100,
        _ body: @escaping @Sendable (Runtime) async throws -> T
    ) throws(Failure) -> [T] {
        var results: [T] = []
        for seed in environmentSeed.map({ $0..<($0 + 1) }) ?? seeds {
            let rt = Runtime.seeded(seed)
            defer { rt.shutdown() }
            do {
                results.append(try rt.block { try await body(rt) })
            } catch {
                throw Failure(seed: seed, error: error)
            }
        }
        return results
    }

    /// `VEGA_SEED`, if set.
    public static var environmentSeed: UInt64? {
        guard let raw = getenv("VEGA_SEED") else { return nil }
        return UInt64(String(cString: raw))
    }
}
