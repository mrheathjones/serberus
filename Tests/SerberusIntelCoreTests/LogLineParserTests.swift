import Foundation
import Testing
@testable import SerberusIntelCore

@Suite("LogLineParser")
struct LogLineParserTests {
    /// A real `log show --style ndjson` record, trimmed to the fields the
    /// parser reads. Field names were taken from live `log` output.
    static let sample = """
        {"timezoneName":"","messageType":"Error","eventType":"logEvent","source":null,\
        "formatString":"denied %{public}@","subsystem":"com.herojoneslabs.serberus",\
        "category":"decisions","processImagePath":"/usr/bin/sudo","processID":4242,\
        "timestamp":"2026-07-16 19:19:06.595808-0400","eventMessage":"denied /usr/bin/jamf recon"}
        """

    @Test("parses a real ndjson record")
    func parsesRecord() throws {
        let entry = try #require(LogLineParser().parse(line: Self.sample))
        #expect(entry.level == .error)
        #expect(entry.subsystem == "com.herojoneslabs.serberus")
        #expect(entry.category == "decisions")
        #expect(entry.message == "denied /usr/bin/jamf recon")
        #expect(entry.processID == 4242)
        #expect(entry.processName == "sudo")
    }

    @Test("skips the `log stream` preamble that arrives on stdout")
    func skipsPreamble() {
        // `log stream --style ndjson` writes this line to STDOUT, interleaved
        // with the JSON — not to stderr. Verified against live output. A
        // strict decoder would throw on the first line of every stream.
        let preamble = #"Filtering the log data using "subsystem BEGINSWITH "com.herojoneslabs.serberus"""#
        #expect(LogLineParser().parse(line: preamble) == nil)
    }

    @Test("skips blanks and malformed JSON rather than throwing")
    func skipsGarbage() {
        let parser = LogLineParser()
        #expect(parser.parse(line: "") == nil)
        #expect(parser.parse(line: "   ") == nil)
        #expect(parser.parse(line: "{not json") == nil)
        #expect(parser.parse(line: "{}") == nil)
    }

    @Test("skips non-logEvent records")
    func skipsNonLogEvents() {
        let activity = """
            {"eventType":"activityCreateEvent","eventMessage":"x","timestamp":"2026-07-16 19:19:06.595808-0400"}
            """
        #expect(LogLineParser().parse(line: activity) == nil)
    }

    @Test("an unknown messageType degrades to Default rather than dropping the line")
    func unknownLevel() throws {
        let line = """
            {"eventType":"logEvent","messageType":"Bananas","subsystem":"com.herojoneslabs.serberus",\
            "category":"pam","eventMessage":"hi","timestamp":"2026-07-16 19:19:06.595808-0400",\
            "processImagePath":"/usr/bin/sudo","processID":1}
            """
        let entry = try #require(LogLineParser().parse(line: line))
        // Losing a log line is worse than mislabelling its severity.
        #expect(entry.level == .default)
    }

    @Test("parses a multi-line document and drops the preamble in place")
    func parsesDocument() {
        let document = [
            #"Filtering the log data using "subsystem == "x"""#,
            Self.sample,
            "",
            Self.sample,
        ].joined(separator: "\n")
        #expect(LogLineParser().parse(document: document).count == 2)
    }

    @Test("level ordering supports 'this level and above' filtering")
    func levelOrdering() {
        #expect(LogLevel.debug.severity < LogLevel.info.severity)
        #expect(LogLevel.info.severity < LogLevel.default.severity)
        #expect(LogLevel.default.severity < LogLevel.error.severity)
        #expect(LogLevel.error.severity < LogLevel.fault.severity)
    }
}

@Suite("LineBuffer")
struct LineBufferTests {
    @Test("holds a partial line until the next read completes it")
    func partialLines() {
        let buffer = LineBuffer()
        // A pipe read can land mid-line; yielding the fragment would corrupt
        // the record.
        #expect(buffer.append(Data(#"{"a":"#.utf8)).isEmpty)
        #expect(buffer.append(Data("1}\n".utf8)) == [#"{"a":1}"#])
    }

    @Test("splits several lines from one read")
    func multipleLines() {
        let buffer = LineBuffer()
        #expect(buffer.append(Data("one\ntwo\nthree\n".utf8)) == ["one", "two", "three"])
    }

    @Test("a trailing fragment is not emitted until terminated")
    func trailingFragment() {
        let buffer = LineBuffer()
        #expect(buffer.append(Data("one\npart".utf8)) == ["one"])
        #expect(buffer.append(Data("ial\n".utf8)) == ["partial"])
    }
}
