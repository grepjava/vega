import Logging
import Vega

extension Runtime {
    /// Log each job that holds a worker for `threshold` or longer, through
    /// swift-log: what tokio-console flags as a task blocking its worker.
    /// Turns on `measurePollTimes`, which costs two clock reads a job;
    /// `logSlowPolls(to: nil)` turns it off again.
    public func logSlowPolls(to logger: Logger?, threshold: Duration = .milliseconds(10),
                             level: Logger.Level = .warning) {
        guard let logger else {
            onSlowPoll = nil
            slowPollThreshold = nil
            measurePollTimes = false
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
