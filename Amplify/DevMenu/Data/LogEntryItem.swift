//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import SwiftUI

/// Data class for each log item in Log Viewer Screen
@available(iOS 13.0, *)
struct LogEntryItem: Identifiable, Hashable {
    var id = UUID()

    /// Log message
    var message: String

    /// Level of the log entry
    var logLevel: LogLevel

    /// Timestamp of the log entry
    var timeStamp: Date

    /// String to display corresponding to `LogLevel`
    var logLevelString: String {
        switch logLevel {
        case .debug:
            return "[debug]"
        case .verbose:
            return "[verbose]"
        case .error:
            return "[error]"
        case .warn:
            return "[warn]"
        case .info:
            return "[info]"
        }
    }

    /// Color of `logLevelString` corresponding to `LogLevel`
    var logLevelTextColor: Color {
        switch logLevel {
        case .debug:
            return Color.gray
        case .verbose:
            return Color.green
        case .error:
            return Color.red
        case .warn:
            return Color.yellow
        case .info:
            return Color.blue
        }
    }
}
