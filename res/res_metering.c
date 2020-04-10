/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2018, USAN, Inc.
 *
 * Daniel Collins <daniel.collins@usan.com>
 * based on sample code by David M. Lee, II <dlee@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \brief Google metering engine
 *
 * This module subscribes to the channel caching topic and issues metering
 * events to the Google billing container.
 *
 * \author Daniel Collins <daniel.collins@usan.com>
 */

/*** MODULEINFO
	<depend>curl</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#include <curl/curl.h>

#include "asterisk/file.h"
#include "asterisk/module.h"
#include "asterisk/stasis_channels.h"
#include "asterisk/stasis_message_router.h"
#include "asterisk/statsd.h"
#include "asterisk/sched.h"
#include "asterisk/time.h"
#include "asterisk/cli.h"

/*! Stasis message router */
static struct stasis_message_router *router;
/*! metering message scheduler */
static struct ast_sched_context *metric_scheduler;
/*! current schedule id */
static int metric_sched_id = 0;
/*! consecutive failure count */
static int consecutive_failures = 0;

static ast_mutex_t count_lock;
static int current_channel_count = 0;
static int interval_max_channel_count = 0;
static struct timeval interval_start;
static struct timeval interval_end;

static int max_consecutive_failures = 2;
static int interval = 5;
static const char *report_url = "http://localhost:4242/report";

static struct timeval next_interval_end(int interval_minutes, struct timeval basis)
{
    struct timeval next = basis;
    next.tv_sec = ((next.tv_sec / (interval * 60)) + 1) * interval * 60;
    next.tv_usec = 0;
    return next;
}

static int ms_until_next_interval(int interval_minutes, struct timeval basis)
{
    struct timeval next_interval = next_interval_end(interval_minutes, basis);
    ast_assert(ast_tvcmp(next_interval, ast_tvnow()) >= 0);
    return ast_tvdiff_ms(next_interval, ast_tvnow());
}

static void crash_asterisk(void)
{
    char *buff = NULL;
    ast_log(LOG_ERROR, "Forcing a process crash\n");
    usleep(1000); /* to let the last few log messages be written */
    memmove(buff, "crashing now", 12); /* that should do it */ 
}

static void stop_asterisk(void)
{
    char template[] = "/tmp/res-metering-XXXXXX";
    int ret;
    RAII_VAR(int, fd, -1, close);

    ast_log(LOG_ERROR, "Shutting down asterisk due to metering failures.\n");

    if ((fd = mkstemp(template)) < 0) {
		ast_log(LOG_WARNING, "Failed to create temporary file to shut down asterisk: %s\n", strerror(errno));
        crash_asterisk();
        return;
	}

	ret = ast_cli_command(fd, "core stop now");
    if (ret != RESULT_SUCCESS) {
        ast_log(LOG_WARNING, "Failed to 'core stop now'\n");
        crash_asterisk();
    }
}

static size_t curl_report_data_callback(char *ptr, size_t size, size_t nmemb, void *data)
{
    ast_log(LOG_DEBUG, "Got unexpected data on usage report -- '%.*s'.\n", (int)(size * nmemb), ptr);
    return size * nmemb;
}

static size_t curl_report_read_callback(char *buffer, size_t size, size_t nitems, char *data)
{
    size_t towrite = 0;
    if (!ast_strlen_zero(data)) {
        size_t datalen = strlen(data);
        towrite = size * nitems;
        if (datalen > towrite) {
            memcpy(buffer, data, towrite);
            /* shift over the remaining data */
            memmove(data, data + towrite, datalen - towrite + 1);
        } else {
            towrite = datalen;
            memcpy(buffer, data, towrite);
            *data = '\0';
        }
    }
    return towrite;
}

static int send_metric_data(const void *_)
{
    int count;
    struct timeval tvstart;
    struct timeval tvend;
    struct ast_json *obj;
    int resched_ms;
    RAII_VAR(struct ast_json *, data, ast_json_object_create(), ast_json_unref);
    RAII_VAR(CURL *, curl, curl_easy_init(), curl_easy_cleanup);

    ast_mutex_lock(&count_lock);
    count = interval_max_channel_count;
    interval_max_channel_count = current_channel_count;
    tvstart = interval_start;
    tvend = interval_end;
    interval_start = interval_end;
    interval_end = next_interval_end(interval, interval_start);
    ast_mutex_unlock(&count_lock);

    if (!data) {
        ast_log(LOG_WARNING, "Error allocating json structure for metric body\n");
    } else if (!curl) {
        ast_log(LOG_WARNING, "Unable to init curl to report metrics\n");
    } else {
        RAII_VAR(char *, body, NULL, ast_json_free);
        RAII_VAR(struct curl_slist *, headers, NULL, curl_slist_free_all);
        RAII_VAR(struct ast_str *, header, ast_str_create(128), ast_free);
        CURLcode res;
        char start[AST_ISO8601_LEN];
        char end[AST_ISO8601_LEN];
        struct ast_tm tmstart = {};
        struct ast_tm tmend = {};
        long http_code = 0;
        
        ast_localtime(&tvstart, &tmstart, NULL);
        ast_localtime(&tvend, &tmend, NULL);

        ast_strftime(start, sizeof(start), "%FT%TZ", &tmstart);
        ast_strftime(end, sizeof(end), "%FT%TZ", &tmend);

        ast_json_object_set(data, "name", ast_json_string_create("concurrentCalls"));
        ast_json_object_set(data, "startTime", ast_json_string_create(start));
        ast_json_object_set(data, "endTime", ast_json_string_create(end));
        obj = ast_json_object_create();
        ast_json_object_set(data, "value", obj);
        ast_json_object_set(obj, "int64Value", ast_json_integer_create(count));
    
        body = ast_json_dump_string(data);

        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_report_data_callback);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "res-metering/1.0");
        curl_easy_setopt(curl, CURLOPT_URL, report_url);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_report_read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, body);
        curl_easy_setopt(curl, CURLOPT_POST, 1);

        ast_str_set(&header, 0, "Content-Length: %d", (int)strlen(body));
        headers = curl_slist_append(headers, ast_str_buffer(header));
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        if (option_debug) {
            ast_log(LOG_DEBUG, "Posting usage metric '%s' to %s\n", body, report_url);
        }

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (res != CURLE_OK || http_code != 200) {
            consecutive_failures++;
            ast_log(LOG_WARNING, "Got error %ld posting metric to %s -- %s\n", http_code, report_url, curl_easy_strerror(res));

            /* try to reset the metrics so if we do eventually get through it's correct */
            ast_mutex_lock(&count_lock);
            interval_max_channel_count = MAX(current_channel_count, count);
            interval_start = tvstart;
            interval_end = next_interval_end(interval, tvend);
            ast_mutex_unlock(&count_lock);

            if (consecutive_failures > max_consecutive_failures) {
                stop_asterisk();
            }
        } else {
            consecutive_failures = 0;
        }
    }

    resched_ms = ms_until_next_interval(interval, ast_tvnow());
    ast_assert(resched_ms <= (interval * 60 * 1000));
    metric_sched_id = ast_sched_add(metric_scheduler, resched_ms, send_metric_data, NULL);
    if (metric_sched_id < 0) {
        ast_log(LOG_WARNING, "Failed to add schedule for metering\n");
    } else if (option_debug) {
        ast_log(LOG_DEBUG, "Scheduled next metering event %dms from now\n", resched_ms);
    }
    return 0;
}

static int update_channel_count(int addend)
{
    int current;
    ast_mutex_lock(&count_lock);
    current_channel_count += addend;
    current = current_channel_count;
    if (current > interval_max_channel_count) {
        interval_max_channel_count = current;
    }
    ast_mutex_unlock(&count_lock);
    return current;
}

/*!
 * \brief Router callback for \ref stasis_cache_update messages.
 * \param data Data pointer given when added to router.
 * \param sub This subscription.
 * \param topic The topic the message was posted to. This is not necessarily the
 *              topic you subscribed to, since messages may be forwarded between
 *              topics.
 * \param message The message itself.
 */
static void channel_updates(void *data, struct stasis_subscription *sub,
	struct stasis_message *message)
{
	/* Since this came from a message router, we know the type of the
	 * message. We can cast the data without checking its type.
	 */
	struct stasis_cache_update *update = stasis_message_data(message);

	/* We're only interested in channel snapshots, so check the type
	 * of the underlying message.
	 */
	if (ast_channel_snapshot_type() != update->type) {
		return;
	}

	/* There are three types of cache updates.
	 * !old && new -> Initial cache entry
	 * old && new -> Updated cache entry
	 * old && !new -> Cache entry removed.
	 */

	if (!update->old_snapshot && update->new_snapshot) {
		/* Initial cache entry; count a channel creation */
        struct ast_channel_snapshot *snapshot = stasis_message_data(update->new_snapshot);
        if (snapshot && !ast_test_flag(&snapshot->flags, AST_FLAG_OUTGOING)) {
            /* do not count outbound channels */
            int count = update_channel_count(+1);
            ast_log(LOG_DEBUG, "Add channel. Current count - %d\n", count);
        }
	} else if (update->old_snapshot && !update->new_snapshot) {
		/* Cache entry removed. Compute the age of the channel and post
		 * that, as well as decrementing the channel count.
		 */
        struct ast_channel_snapshot *snapshot = stasis_message_data(update->old_snapshot);
        if (snapshot && !ast_test_flag(&snapshot->flags, AST_FLAG_OUTGOING)) {
            /* do not count outbound channels */
            int count = update_channel_count(-1);
            ast_log(LOG_DEBUG, "Remove channel. Current count - %d\n", count);
        }
	}
}

/*!
 * \brief Router callback for any message that doesn't otherwise have a route.
 * \param data Data pointer given when added to router.
 * \param sub This subscription.
 * \param topic The topic the message was posted to. This is not necessarily the
 *              topic you subscribed to, since messages may be forwarded between
 *              topics.
 * \param message The message itself.
 */
static void default_route(void *data, struct stasis_subscription *sub,
	struct stasis_message *message)
{
	if (stasis_subscription_final_message(sub, message)) {
		/* Much like with the regular subscription, you may need to
		 * perform some cleanup when done with a message router. You
		 * can look for the final message in the default route.
		 */
		return;
	}
}

static int unload_module(void)
{
    if (metric_scheduler) {
        ast_sched_context_destroy(metric_scheduler);
    }
    if (router) {
        stasis_message_router_unsubscribe_and_join(router);
        router = NULL;
    }
    ast_mutex_destroy(&count_lock);
	return 0;
}

static void load_config(void)
{
	RAII_VAR(struct ast_config *, cfg, NULL, ast_config_destroy);
	struct ast_flags config_flags = { 0 };
    const char *val;

	cfg = ast_config_load("res_metering.conf", config_flags);
		
    if (cfg == CONFIG_STATUS_FILEINVALID) {
        ast_log(LOG_WARNING, "Configuration file invalid\n");
        cfg = ast_config_new();
    } else if (cfg == CONFIG_STATUS_FILEMISSING) {
        ast_log(LOG_WARNING, "Configuration not found, using defaults\n");
        cfg = ast_config_new();
    }
		
    val = ast_variable_retrieve(cfg, "general", "interval");
    if (!ast_strlen_zero(val)) {
        int i;
        if (sscanf(val, "%d", &i) == 1) {
            if (i >= 1 && i <= 60) {
                interval = i;
            } else {
                ast_log(LOG_WARNING, "'interval' exceeds allowable limits.\n");
            }
        } else {
            ast_log(LOG_WARNING, "'interval' must be numeric\n");
        }
    }

    val = ast_variable_retrieve(cfg, "general", "max_consecutive_failures");
    if (!ast_strlen_zero(val)) {
        int i;
        if (sscanf(val, "%d", &i) == 1) {
            max_consecutive_failures = i;
        } else {
            ast_log(LOG_WARNING, "'max_consecutive_failures' must be numeric\n");
        }
    }

    val = ast_variable_retrieve(cfg, "general", "report_url");
    if (!ast_strlen_zero(val)) {
        report_url = ast_strdup(val);
    }
}

static int load_module(void)
{
    int sched_ms;

    ast_mutex_init(&count_lock);

    load_config();

    metric_scheduler = ast_sched_context_create();
    if (!metric_scheduler) {
        ast_log(LOG_WARNING, "Failed to initialize scheduling context\n");
        return AST_MODULE_LOAD_DECLINE;
    }

    if (ast_sched_start_thread(metric_scheduler)) {
        ast_log(LOG_WARNING, "Failed to create scheduler thread\n");
        return AST_MODULE_LOAD_DECLINE;
    }

	/* You can create a message router to route messages by type */
	router = stasis_message_router_create(
		ast_channel_topic_all_cached());
	if (!router) {
        ast_log(LOG_WARNING, "Failed to initialize statis router\n");
        unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}
	stasis_message_router_add(router, stasis_cache_update_type(),
		channel_updates, NULL);
	stasis_message_router_set_default(router, default_route, NULL);

    interval_start = ast_tvnow();
    interval_end = next_interval_end(interval, interval_start);
    sched_ms = ms_until_next_interval(interval, ast_tvnow());
    ast_assert(sched_ms <= (interval * 60 * 1000));

    metric_sched_id = ast_sched_add(metric_scheduler, sched_ms, send_metric_data, NULL);
    if (metric_sched_id < 0) {
        ast_log(LOG_WARNING, "Failed to schedule metric event\n");
        unload_module();
        return AST_MODULE_LOAD_DECLINE;
    } else {
        ast_log(LOG_DEBUG, "Scheduled first metric event %dms from now\n", sched_ms);
    }

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Usage metric tracking",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module
);