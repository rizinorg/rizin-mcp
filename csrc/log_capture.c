// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later

// RzLogCallback is variadic, which stable Rust cannot define, so this forwards
// the formatted line of every Rizin log message to a plain Rust function.

#include <rz_util/rz_log.h>

typedef void (*RizinMcpLogSink)(const char *output, int level);

static RizinMcpLogSink log_sink;

static void forward_log(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	(void)funcname;
	(void)filename;
	(void)lineno;
	(void)tag;
	(void)fmtstr;
	if (log_sink && output) {
		log_sink(output, (int)level);
	}
}

/**
 * \brief Route Rizin log messages to \p sink instead of stderr
 *
 * \param sink Receives each formatted message and its RzLogLevel, or NULL to
 *        restore printing to stderr
 */
void rizin_mcp_log_set_sink(RizinMcpLogSink sink) {
	// Checked against the header, so a changed callback signature fails the build.
	RzLogCallback cb = forward_log;
	log_sink = sink;
	if (sink) {
		rz_log_add_callback(cb);
	} else {
		rz_log_del_callback(cb);
	}
}
