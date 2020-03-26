// SPDX-License-Identifier: GPL-2.0-only
/*
 * Chrome Trace Format writing support.
 *
 * // TODO ASK Vincent about those copyrights...
 * Copyright (C) 2020, Alexandre Ghiti <alex@ghiti.fr>
 */

#include <errno.h>
#include <inttypes.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <traceevent/event-parse.h>
#include "asm/bug.h"
#include "data-convert-chrome.h"
#include "session.h"
#include "debug.h"
#include "tool.h"
#include "evlist.h"
#include "evsel.h"
#include "machine.h"
#include "config.h"
#include "../../bpf/bpftool/json_writer.h"
#include <linux/ctype.h>
#include <linux/err.h>

#define pr_N(n, fmt, ...) \
	eprintf(n, debug_data_convert, fmt, ##__VA_ARGS__)

#define pr(fmt, ...)  pr_N(1, pr_fmt(fmt), ##__VA_ARGS__)
#define pr2(fmt, ...) pr_N(2, pr_fmt(fmt), ##__VA_ARGS__)

#define pr_time2(t, fmt, ...) pr_time_N(2, debug_data_convert, t, pr_fmt(fmt), ##__VA_ARGS__)

#define MAX_CPUS	4096

struct chrometf_writer {
	/* writer primitives */
	json_writer_t		 *writer;

};

struct convert {
	struct perf_tool	tool;
	// TODO might be a union and gloabl struct convert def
	struct chrometf_writer	writer;

	u64			events_size;
	u64			events_count;
	u64			non_sample_count;

	/* Ordered events configured queue size. */
	u64			queue_size;
};

static int add_tracepoint_field_value(struct chrometf_writer *cw,
                                      __attribute__((unused)) struct perf_sample *sample,
                                      struct format_field *fmtf)
{
        const char *name; // = fmtf->name;
        void *data = sample->raw_data;
        unsigned long flags = fmtf->flags;
        //unsigned int n_items;
        //unsigned int i;
        unsigned int offset;
        unsigned int len;
        //int ret;
	//char tmp[64];

        name = fmtf->alias;
        offset = fmtf->offset;
        len = fmtf->size;
        //if (flags & TEP_FIELD_IS_STRING)
        //        flags &= ~TEP_FIELD_IS_ARRAY;

        //if (flags & TEP_FIELD_IS_DYNAMIC) {
        //        unsigned long long tmp_val;

        //        tmp_val = tep_read_number(fmtf->event->tep,
        //                                  data + offset, len);
        //        offset = tmp_val;
        //        len = offset >> 16;
        //        offset &= 0xffff;
        //}

        //if (flags & TEP_FIELD_IS_ARRAY) {
	//	printf("ARRAY type not handled\n");
        //        len = fmtf->size / fmtf->arraylen;
        //        n_items = fmtf->arraylen;
        //} else {
        //        n_items = 1;
        //        array_field = NULL;
        //}

	if (flags & FIELD_IS_STRING)
		jsonw_string_field(cw->writer, name, "");
	else {
		unsigned long long value_int;
		char tmp[64];

		value_int = tep_read_number(
					    fmtf->event->pevent,
					    data + offset /*+ i * len*/, len);

		if (!(flags & FIELD_IS_SIGNED))
			sprintf(tmp, "0x%llx", (long long)value_int);
		else
			sprintf(tmp, "0x%llx", value_int);

		jsonw_string_field(cw->writer, name, tmp);
	}



//        type = get_tracepoint_field_type(cw, fmtf);
//
//	for (i = 0; i < n_items; i++) {
//                if (flags & TEP_FIELD_IS_ARRAY)
//			jsonw_start_array(cw->writer);
//
//                if (flags & TEP_FIELD_IS_STRING)
//			jsonw_string_field(cw->writer, fmtf);
//                        ret = string_set_value(field, data + offset + i * len);
//                else {
//                        unsigned long long value_int;
//
//                        value_int = tep_read_number(
//                                        fmtf->event->tep,
//                                        data + offset + i * len, len);
//
//                        if (!(flags & TEP_FIELD_IS_SIGNED))
//                                ret = bt_ctf_field_unsigned_integer_set_value(
//                                                field, value_int);
//                        else
//                                ret = bt_ctf_field_signed_integer_set_value(
//                                                field, adjust_signedness(value_int, len));
//                }
//
//                if (ret) {
//                        pr_err("failed to set file value %s\n", name);
//                        goto err_put_field;
//                }
//                if (!(flags & TEP_FIELD_IS_ARRAY)) {
//                        ret = bt_ctf_event_set_payload(event, name, field);
//                        if (ret) {
//                                pr_err("failed to set payload %s\n", name);
//                                goto err_put_field;
//                        }
//                }
//                bt_ctf_field_put(field);
//        }
//        if (flags & TEP_FIELD_IS_ARRAY) {
//                ret = bt_ctf_event_set_payload(event, name, array_field);
//                if (ret) {
//                        pr_err("Failed add payload array %s\n", name);
//                        return -1;
//                }
//                bt_ctf_field_put(array_field);
//        }
        return 0;
//
//err_put_field:
//        bt_ctf_field_put(field);
//        return -1;
}

static int add_tracepoint_fields_values(struct chrometf_writer *cw,
                                        struct format_field *fields,
                                        struct perf_sample *sample)
{
        struct format_field *field;
        int ret;

        for (field = fields; field; field = field->next) {
                ret = add_tracepoint_field_value(cw, sample, field);
                if (ret)
                        return -1;

        }
        return 0;
}

static int add_tracepoint_values(struct chrometf_writer *cw,
                                 struct perf_evsel *evsel,
                                 struct perf_sample *sample)
{
        struct format_field *common_fields = evsel->tp_format->format.common_fields;
        struct format_field *fields        = evsel->tp_format->format.fields;
        int ret;

        ret = add_tracepoint_fields_values(cw, common_fields, sample);
        if (!ret)
                ret = add_tracepoint_fields_values(cw, fields, sample);

        return ret;
}

static int process_sample_event(struct perf_tool *tool,
				union perf_event *_event,
				struct perf_sample *sample,
				struct perf_evsel *evsel,
				struct machine *machine __maybe_unused)
{
	struct convert *c = container_of(tool, struct convert, tool);
	struct chrometf_writer *cw = &c->writer;
	char tmp[64];
	int ret;

	/* update stats */
	c->events_count++;
	c->events_size += _event->header.size;

	pr_time2(sample->time, "sample %" PRIu64 "\n", c->events_count);

	jsonw_start_object(cw->writer);

	jsonw_string_field(cw->writer, "name", evsel->name);
	jsonw_string_field(cw->writer, "cat", "dpu");
	sprintf(tmp, "%u", sample->pid);
	jsonw_string_field(cw->writer, "pid", tmp);
	sprintf(tmp, "%u", sample->tid);
	jsonw_string_field(cw->writer, "tid", tmp);
	sprintf(tmp, "%lu", sample->time);
	jsonw_string_field(cw->writer, "ts", tmp);

	if (strstr(evsel->name, "exit__return"))
		jsonw_string_field(cw->writer, "ph", "E");
	else if (strstr(evsel->name, "__entry"))
		jsonw_string_field(cw->writer, "ph", "B");
	else
		jsonw_string_field(cw->writer, "ph", "I");

	jsonw_name(cw->writer, "args");
	jsonw_start_object(cw->writer);
	if (evsel->attr.type == PERF_TYPE_TRACEPOINT) {
		ret = add_tracepoint_values(cw, evsel, sample);
		if (ret)
			return -1;
	}
	jsonw_end_object(cw->writer);

	jsonw_end_object(cw->writer);

	return 0;
}

#define __FUNC_PROCESS_NON_SAMPLE(_name, body)  \
static int process_##_name##_event(struct perf_tool *tool,      \
                                   union perf_event *_event,    \
                                   struct perf_sample *sample,  \
                                   struct machine *machine)     \
{                                                               \
        struct convert *c = container_of(tool, struct convert, tool);\
                                                                \
        c->non_sample_count++;                                  \
        c->events_size += _event->header.size;                  \
                                                                \
        return perf_event__process_##_name(tool, _event, sample, machine);\
}

__FUNC_PROCESS_NON_SAMPLE(comm,
        __NON_SAMPLE_SET_FIELD(comm, u32, pid);
        __NON_SAMPLE_SET_FIELD(comm, u32, tid);
        __NON_SAMPLE_SET_FIELD(comm, string, comm);
)
__FUNC_PROCESS_NON_SAMPLE(fork,
        __NON_SAMPLE_SET_FIELD(fork, u32, pid);
        __NON_SAMPLE_SET_FIELD(fork, u32, ppid);
        __NON_SAMPLE_SET_FIELD(fork, u32, tid);
        __NON_SAMPLE_SET_FIELD(fork, u32, ptid);
        __NON_SAMPLE_SET_FIELD(fork, u64, time);
)

__FUNC_PROCESS_NON_SAMPLE(exit,
        __NON_SAMPLE_SET_FIELD(fork, u32, pid);
        __NON_SAMPLE_SET_FIELD(fork, u32, ppid);
        __NON_SAMPLE_SET_FIELD(fork, u32, tid);
        __NON_SAMPLE_SET_FIELD(fork, u32, ptid);
        __NON_SAMPLE_SET_FIELD(fork, u64, time);
)
__FUNC_PROCESS_NON_SAMPLE(mmap,
        __NON_SAMPLE_SET_FIELD(mmap, u32, pid);
        __NON_SAMPLE_SET_FIELD(mmap, u32, tid);
        __NON_SAMPLE_SET_FIELD(mmap, u64_hex, start);
        __NON_SAMPLE_SET_FIELD(mmap, string, filename);
)
__FUNC_PROCESS_NON_SAMPLE(mmap2,
        __NON_SAMPLE_SET_FIELD(mmap2, u32, pid);
        __NON_SAMPLE_SET_FIELD(mmap2, u32, tid);
        __NON_SAMPLE_SET_FIELD(mmap2, u64_hex, start);
        __NON_SAMPLE_SET_FIELD(mmap2, string, filename);
)

static void cleanup_events(struct perf_session *session)
{
	struct perf_evlist *evlist = session->evlist;

	perf_evlist__delete(evlist);
	session->evlist = NULL;
}

static void chrometf_writer__cleanup(struct chrometf_writer *cw)
{
	jsonw_destroy(&cw->writer);

	/* and NULL all the pointers */
	memset(cw, 0, sizeof(*cw));
}

static int chrometf_writer__init(struct chrometf_writer *cw, const char *path)
{
	json_writer_t			*writer;
	FILE				*f;

	/* Chrome Trace Format writer */
	f = fopen(path, "w");
	if (f == NULL)
		return -1;

	writer = jsonw_new(f);
	if (!writer)
		goto err;

	jsonw_pretty(writer, true);

	cw->writer = writer;

	return 0;

err:
	pr_err("Failed to setup CTF writer.\n");
	return -1;
}

static int convert__config(const char *var, const char *value, void *cb)
{
	struct convert *c = cb;

	if (!strcmp(var, "convert.queue-size"))
		return perf_config_u64(&c->queue_size, var, value);

	return 0;
}

int convert__perf2chrometf(const char *input, const char *path,
			 struct perf_data_convert_opts *opts)
{
	struct perf_session *session;
	struct perf_data data = {
		.file.path	   = input,
		.mode      = PERF_DATA_MODE_READ,
		.force     = opts->force,
	};
	struct convert c = {
		.tool = {
			.sample          = process_sample_event,
			.mmap            = perf_event__process_mmap,
			.mmap2           = perf_event__process_mmap2,
			.comm            = perf_event__process_comm,
			.exit            = perf_event__process_exit,
			.fork            = perf_event__process_fork,
			.lost            = perf_event__process_lost,
			.tracing_data    = perf_event__process_tracing_data,
			.build_id        = perf_event__process_build_id,
			.namespaces      = perf_event__process_namespaces,
			.ordered_events  = true,
			.ordering_requires_timestamps = true,
		},
	};
	struct chrometf_writer *cw = &c.writer;
	int err;

	if (opts->all) {
		c.tool.comm = process_comm_event;
		c.tool.exit = process_exit_event;
		c.tool.fork = process_fork_event;
		c.tool.mmap = process_mmap_event;
		c.tool.mmap2 = process_mmap2_event;
	}

	err = perf_config(convert__config, &c);
	if (err)
		return err;

	/* Chrome Trace Format writer */
	if (chrometf_writer__init(cw, path))
		return -1;

	err = -1;
	/* perf.data session */
	session = perf_session__new(&data, 0, &c.tool);
	if (IS_ERR(session)) {
		err = PTR_ERR(session);
		goto free_writer;
	}

	if (c.queue_size) {
		ordered_events__set_alloc_size(&session->ordered_events,
					       c.queue_size);
	}

	jsonw_start_object(cw->writer);
	jsonw_name(cw->writer, "traceEvents");
	jsonw_start_array(cw->writer);

	err = perf_session__process_events(session);
	if (err)
		pr_err("Error during conversion.\n");

	jsonw_end_array(cw->writer);
	jsonw_end_object(cw->writer);

	fprintf(stderr,
		"[ perf data convert: Converted '%s' into Chrome Trace Format data '%s' ]\n",
		data.file.path, path);

	fprintf(stderr,
		"[ perf data convert: Converted and wrote %.3f MB (%" PRIu64 " samples",
		(double) c.events_size / 1024.0 / 1024.0,
		c.events_count);

	if (!c.non_sample_count)
		fprintf(stderr, ") ]\n");
	else
		fprintf(stderr, ", %" PRIu64 " non-samples) ]\n", c.non_sample_count);

	cleanup_events(session);
	perf_session__delete(session);
	chrometf_writer__cleanup(cw);

	return err;

	perf_session__delete(session);
free_writer:
	chrometf_writer__cleanup(cw);
	pr_err("Error during conversion setup.\n");
	return err;
}
