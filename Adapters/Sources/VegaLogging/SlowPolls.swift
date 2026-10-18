import Logging
import Vega

extension Runtime {
    /// Log each job that holds a worker for `threshold` or longer, through
    /// swift-log: what tokio-console flags as a task blocking its worker.
    /// It takes the runtime's one `onSlowPoll` hook, replacing any other,
    /// and turns on `measurePollTimes`, which costs two clock reads a job.
    /// `logSlowPolls(to: nil)` stops the logging and gives the hook back;
    /// measuring stays on, since the poll-time metrics may be read too
    /// (turn `measurePollTimes` off yourself if nothing else needs it).
    public func logSlowPolls(to logger: Logger?, threshold: Duration = .milliseconds(10),
                             level: Logger.Level = .warning) {
        guard let logger else {
            onSlowPoll = nil
            return
        }
        slowPollThreshold = threshold
        onSlowPoll = { poll in
            logger.log(level: level, "a job held its worker too long",
                       metadata: ["worker": "\(poll.worker)", "duration": "\(poll.duration)"])
        }
        measurePollTimes = true
    }
}
