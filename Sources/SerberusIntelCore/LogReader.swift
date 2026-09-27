import Foundation

/// Accumulates piped bytes into whole lines.
///
/// `log(1)` writes into a pipe, so a read can land mid-line; yielding a
/// partial line would drop the record. The trailing fragment is held until
/// the next read completes it.
final class LineBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var pending = Data()

    /// Appends bytes and returns every complete line they finished.
    func append(_ data: Data) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        pending.append(data)

        var lines: [String] = []
        let newline = UInt8(ascii: "\n")
        while let index = pending.firstIndex(of: newline) {
            let lineData = pending[pending.startIndex..<index]
            lines.append(String(decoding: lineData, as: UTF8.self))
            pending = pending[(index + 1)...]
        }
        // Re-base so the buffer's indices don't grow unbounded across reads.
        pending = Data(pending)
        return lines
    }
}

/// Errors from driving `log(1)`.
public enum LogReaderError: Error, LocalizedError, Equatable {
    case launchFailed(String)
    case toolFailed(exitCode: Int32, stderr: String)

    public var errorDescription: String? {
        switch self {
        case let .launchFailed(reason):
            return "Could not run /usr/bin/log: \(reason)"
        case let .toolFailed(exitCode, stderr):
            let detail = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            return "log exited \(exitCode)\(detail.isEmpty ? "" : ": \(detail)")"
        }
    }
}

/// Runs historical (`log show --last …`) queries.
public struct LogReader: Sendable {
    private let query: LogQuery

    public init(query: LogQuery = LogQuery()) {
        self.query = query
    }

    /// Fetches entries for `window`.
    ///
    /// Reads stdout and stderr concurrently. Draining them serially would
    /// deadlock the moment either pipe's buffer fills — `log show` over a
    /// 7-day window produces far more than a pipe buffer holds.
    public func show(window: LogWindow) async throws -> [LogEntry] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: LogQuery.logToolPath)
        process.arguments = query.showArguments(window: window)

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
        } catch {
            throw LogReaderError.launchFailed(error.localizedDescription)
        }

        async let outputData = Self.readToEnd(outputPipe.fileHandleForReading)
        async let errorData = Self.readToEnd(errorPipe.fileHandleForReading)
        let (output, errorOutput) = await (outputData, errorData)

        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw LogReaderError.toolFailed(
                exitCode: process.terminationStatus,
                stderr: String(decoding: errorOutput, as: UTF8.self)
            )
        }

        let parser = LogLineParser()
        return parser.parse(document: String(decoding: output, as: UTF8.self))
    }

    private static func readToEnd(_ handle: FileHandle) async -> Data {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let data = (try? handle.readToEnd()) ?? Data()
                continuation.resume(returning: data)
            }
        }
    }
}

/// Drives a live `log stream` and publishes entries as they arrive.
public final class LogStreamer: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?

    public init() {}

    /// Starts streaming. The stream finishes when `log` exits or the consumer
    /// cancels; cancelling the task terminates the child process via
    /// `onTermination`, so no orphan `log` survives the window closing.
    public func stream(query: LogQuery = LogQuery()) -> AsyncStream<LogEntry> {
        AsyncStream { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: LogQuery.logToolPath)
            process.arguments = query.streamArguments()

            let pipe = Pipe()
            process.standardOutput = pipe
            // `log stream` puts its "Filtering the log data using …" preamble
            // on stdout, not stderr; the parser drops it. stderr carries only
            // real errors and is not needed for the tail.
            process.standardError = FileHandle.nullDevice

            let parser = LogLineParser()
            let buffer = LineBuffer()

            pipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                guard !data.isEmpty else { return }
                for line in buffer.append(data) {
                    if let entry = parser.parse(line: line) {
                        continuation.yield(entry)
                    }
                }
            }

            process.terminationHandler = { _ in
                pipe.fileHandleForReading.readabilityHandler = nil
                continuation.finish()
            }

            continuation.onTermination = { [weak self] _ in
                self?.stop()
            }

            do {
                try process.run()
            } catch {
                continuation.finish()
                return
            }

            lock.lock()
            self.process = process
            lock.unlock()
        }
    }

    /// Terminates the running `log stream`, if any.
    public func stop() {
        lock.lock()
        let running = process
        process = nil
        lock.unlock()
        if running?.isRunning == true {
            running?.terminate()
        }
    }
}
